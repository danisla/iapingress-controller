package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ghodss/yaml"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	compute "google.golang.org/api/compute/v1"
	servicemanagement "google.golang.org/api/servicemanagement/v1"
	corev1 "k8s.io/api/core/v1"
	v1beta1 "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var (
	config            Config
	templatePath      string
	clientIDPath      string
	clientSecretPath  string
	defaultIAMRole    string
	espContainerImage string
)

func init() {
	templatePath = getenv("TEMPLATE_PATH", "/opt/app")
	clientIDPath = getenv("OAUTH_CLIENT_ID_PATH", "/var/run/secrets/oauth/CLIENT_ID")
	clientSecretPath = getenv("OAUTH_CLIENT_SECRET_PATH", "/var/run/secrets/oauth/CLIENT_SECRET")
	defaultIAMRole = getenv("DEFAULT_IAM_ROLE", "roles/iap.httpsResourceAccessor")
	espContainerImage = getenv("ESP_CONTAINER_IMAGE", "gcr.io/endpoints-release/endpoints-runtime:1")

	config = Config{
		Project:    "", // Derived from instance metadata server
		ProjectNum: "", // Derived from instance metadata server
	}

	if err := config.loadAndValidate(); err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
}

func main() {

	http.HandleFunc("/healthz", healthzHandler())
	http.HandleFunc("/", lambdaHandler())

	log.Printf("[INFO] Initialized controller on port 80\n")
	log.Fatal(http.ListenAndServe(":80", nil))
}

func healthzHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK\n")
	}
}

func lambdaHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Unsupported method\n")
			return
		}

		var req LambdaRequest
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&req); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("[ERROR] Could not parse LambdaRequest: %v", err)
			return
		}

		resp, err := sync(&req.Parent, &req.Children)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("[ERROR] Could not sync state: %v", err)
			return
		}

		data, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("[ERROR] Could not generate LambdaResponse: %v", err)
			return
		}
		fmt.Fprintf(w, string(data))
	}
}

func sync(parent *IapIngress, children *IapIngresControllerRequestChildren) (*LambdaResponse, error) {
	status := makeStatus(parent, children)
	currState := status.StateCurrent
	if currState == "" {
		currState = StateIdle
	}
	desiredChildren := make([]interface{}, 0)
	nextState := currState[0:1] + currState[1:] // string copy of currState

	changed := changeDetected(parent, children, status)
	hostBackends := makeHostBackends(parent)

	if currState == StateIdle && changed {
		// Add the IAM role
		role := parent.Spec.IAPProjectAuthz.Role
		if role == "" {
			role = defaultIAMRole
		}
		members := parent.Spec.IAPProjectAuthz.Members
		log.Printf("[INFO] Updating IAM role '%s' with %d members", role, len(members))

		// Get the current project policy.
		policy, err := config.clientResourceManager.Projects.GetIamPolicy(config.Project, &(cloudresourcemanager.GetIamPolicyRequest{})).Do()
		if err != nil {
			log.Printf("[ERROR] Failed to get IAM policy for project: %s", config.Project)
			return nil, err
		}
		newPolicy := cloudresourcemanager.Policy{
			Version: 1,
		}
		for _, binding := range (*policy).Bindings {
			if (*binding).Role != role {
				newPolicy.Bindings = append(newPolicy.Bindings, binding)
			}
		}
		newPolicy.Bindings = append(newPolicy.Bindings, &cloudresourcemanager.Binding{
			Members: members,
			Role:    role,
		})

		// Set the new policy.
		_, err = config.clientResourceManager.Projects.SetIamPolicy(config.Project, &(cloudresourcemanager.SetIamPolicyRequest{
			Policy: &newPolicy,
		})).Do()
		if err != nil {
			log.Printf("[ERROR] Failed to set new IAM policy: %v", err)
			return nil, err
		}

		status.Authorization = fmt.Sprintf("%d members", len(members))

		// Create the Kuberntes Ingress resource
		log.Printf("[INFO] Creating Ingress: %s", parent.Name)
		ing := makeIngress(parent)
		desiredChildren = append(desiredChildren, ing)

		// Create the ESP service for each host
		for host, svcSpec := range hostBackends {
			if svcSpec.IAP.CreateESP {
				log.Printf("[INFO] Creating ESP Service: %s-esp", svcSpec.ServiceName)
				svc, err := makeESPService(parent.Namespace, svcSpec.ServiceName, host)
				if err != nil {
					log.Printf("[ERROR] Failed to create ESP service resource from template: %v", err)
					return nil, err
				}
				desiredChildren = append(desiredChildren, svc)
			} else {
				// Lookup existing service
				svc, err := config.clientset.CoreV1().Services(parent.Namespace).Get(svcSpec.ServiceName, metav1.GetOptions{})
				if err != nil {
					log.Printf("[ERROR] Existing service not found: %s", svcSpec.ServiceName)
					return nil, err
				}
				if svc.Spec.Type != corev1.ServiceTypeNodePort {
					log.Printf("[ERROR] Existing service is not type=NodePort, service: %s, type: %s", svc.Namespace, svc.Spec.Type)
					return nil, err
				}
				if status.StateData.NodePorts == nil {
					status.StateData.NodePorts = make(map[string]string)
				}
				status.StateData.NodePorts[host] = strconv.Itoa(int(svc.Spec.Ports[0].NodePort))
			}
		}

		nextState = StateIPPending

		// status.LastAppliedSig = calcParentSig(parent, "")
	}

	// Claim the ingress.
	if ing, ok := children.Ingresses[parent.Name]; ok == true {
		desiredChildren = append(desiredChildren, ing)
	}

	// Claim the ESP services, replicasets and configmaps
	for _, svcSpec := range hostBackends {
		espName := fmt.Sprintf("%s-esp", svcSpec.ServiceName)
		if svc, ok := children.Services[espName]; ok == true {
			desiredChildren = append(desiredChildren, svc)
		}
		if rs, ok := children.ReplicaSets[espName]; ok == true {
			desiredChildren = append(desiredChildren, rs)
		}
		if cm, ok := children.ConfigMaps[espName]; ok == true {
			desiredChildren = append(desiredChildren, cm)
		}
	}

	if currState == StateIPPending {
		if ing, ok := children.Ingresses[parent.Name]; ok == true {
			if len(ing.Status.LoadBalancer.Ingress) > 0 {
				if ing.Status.LoadBalancer.Ingress[0].IP != "" {
					status.Address = ing.Status.LoadBalancer.Ingress[0].IP
					log.Printf("[INFO] Ingress IP found: %s", status.Address)
					nextState = StateBackendSvcPending
				}
			}
		}
	}

	if currState == StateBackendSvcPending || currState == StateIAPUpdatePending {
		// Get list of backends created by the GCE ingress controller.
		var svcBackendNames []string
		var ingBackends []string
		if ing, ok := children.Ingresses[parent.Name]; ok == true {
			ingBackends = getIngBackends(&ing)
		}

		for _, bsName := range ingBackends {
			// Match backend with services.
			for host, svcSpec := range hostBackends {
				svcName := fmt.Sprintf("%s-esp", svcSpec.ServiceName)

				var nodePort string
				if svcSpec.IAP.CreateESP {
					nodePort = strconv.Itoa(int(children.Services[svcName].Spec.Ports[0].NodePort))
				} else {
					// Get NodePort from state data
					nodePort = status.StateData.NodePorts[host]
				}

				bsPort := strings.Split(bsName, "-")[2]
				if bsPort == nodePort {
					svcBackendNames = append(svcBackendNames, bsName)
					bsData := BackendServiceStateData{
						Name: bsName,
					}
					if status.StateData.Backends == nil {
						status.StateData.Backends = make(map[string]BackendServiceStateData)
					}
					status.StateData.Backends[host] = bsData
					status.Services[host].Backend = bsName
				}
			}
		}

		// Get full description of backends from GCE API.
		backendsList, err := config.clientCompute.BackendServices.List(config.Project).Do()
		if err != nil {
			log.Printf("[ERROR] Failed to list Compute Engine backends: %v", err)
			return nil, err
		}

		backendPattern, err := regexp.Compile(fmt.Sprintf("(%s)", strings.Join(svcBackendNames, "|")))
		if err != nil {
			log.Printf("[ERROR] Failed to compile backend pattern: %v", err)
			return nil, err
		}

		// Filter backends by those found in the ingress annotation.
		var backends []compute.BackendService
		for _, backend := range backendsList.Items {
			if backendPattern.MatchString(backend.Name) {
				backends = append(backends, *backend)
			}
		}

		// Join service specs with backends and build BackendServiceStateData map.
		status.StateData.BackendsReady = true
		backendServicesMap := make(map[string]compute.BackendService)
		for host, svcSpec := range hostBackends {
			svcName := fmt.Sprintf("%s-esp", svcSpec.ServiceName)

			var nodePort string
			if svcSpec.IAP.CreateESP {
				nodePort = strconv.Itoa(int(children.Services[svcName].Spec.Ports[0].NodePort))
			} else {
				// Get NodePort from state data
				nodePort = status.StateData.NodePorts[host]
			}

			bsFound := false
			for _, bs := range backends {
				bsPort := strings.Split(bs.Name, "-")[2]
				if bsPort == nodePort {
					bsFound = true
					backendServicesMap[host] = bs
					bsData := BackendServiceStateData{
						Name: bs.Name,
						ID:   strconv.Itoa(int(bs.Id)),
						IAP:  false,
					}
					if bs.Iap != nil {
						bsData.IAP = bs.Iap.Enabled
					}
					if status.StateData.Backends == nil {
						status.StateData.Backends = make(map[string]BackendServiceStateData)
					}
					status.StateData.Backends[host] = bsData
					status.Services[host].Backend = string(bs.Name)
				}
			}
			status.StateData.BackendsReady = status.StateData.BackendsReady && bsFound
		}

		if status.StateData.BackendsReady == true {
			// Update IAP on the backends
			for host, backend := range backendServicesMap {
				if hostBackends[host].IAP.Enabled {
					if backend.Iap == nil || backend.Iap.Enabled == false {
						log.Printf("[INFO] Enabling IAP on backend service: %s, enabled=%v", backend.Name, hostBackends[host].IAP.Enabled)
						secretSha256 := fmt.Sprintf("%x", sha256.Sum256([]byte(config.OAuthClientSecret)))
						bsPatch := &compute.BackendService{
							Iap: &compute.BackendServiceIAP{
								Enabled:                  true,
								Oauth2ClientId:           config.OAuthClientID,
								Oauth2ClientSecret:       config.OAuthClientSecret,
								Oauth2ClientSecretSha256: secretSha256,
							},
						}
						_, err := config.clientCompute.BackendServices.Patch(config.Project, backend.Name, bsPatch).Do()
						if err != nil {
							log.Printf("[WARN] Error when updating IAP on backend: %s: %v", backend.Name, err)
						}
					}
				} else {
					status.Services[host].IAP = "Disabled"
				}
			}
			nextState = StateIAPUpdatePending

			status.LastAppliedSig = calcParentSig(parent, strings.Join(ingBackends, ","))
		}

		if currState == StateIAPUpdatePending {
			// Wait for IAP update to complete
			allUpdated := true
			for host, backend := range status.StateData.Backends {
				if hostBackends[host].IAP.Enabled {
					if backend.IAP == true {
						log.Printf("[INFO] IAP enabled on backend: %s", backend.Name)
						status.Services[host].IAP = "Enabled"
					} else {
						allUpdated = false
					}
				}
			}
			if allUpdated {
				// Check if endpoint service exists, if not then create it.
				for host := range hostBackends {
					ep := status.Services[host].Endpoint
					currService, err := config.clientServiceMan.Services.Get(ep).Do()
					if (err != nil && strings.Contains(err.Error(), "not found or permission denied")) || currService.HTTPStatusCode == 403 {
						log.Printf("[INFO] Service does not yet exist, creating: %s", ep)
						_, err := config.clientServiceMan.Services.Create(&servicemanagement.ManagedService{
							ProducerProjectId: config.Project,
							ServiceName:       ep,
						}).Do()
						if err != nil {
							log.Printf("[ERROR] Failed to creat Cloud Endpoints service: serviceName: %s, err: %v", ep, err)
						}
					}
				}
				nextState = StateEndpointCreatePending
			}
		}
	}

	if currState == StateEndpointCreatePending {
		// Submit endpoint config if services exist.
		allSubmitted := true
		for host := range hostBackends {
			ep := status.Services[host].Endpoint
			_, err := config.clientServiceMan.Services.Get(ep).Do()
			if err == nil {
				log.Printf("[INFO] Endpoint created: %s", ep)

				// Service created, submit.
				backend := status.StateData.Backends[host]
				jwtAud := makeJWTAudience(config.ProjectNum, backend.ID)
				sig := makeOpenAPISig(ep, jwtAud, status.Address)
				openAPISpec, err := makeOpenAPI(ep, jwtAud, status.Address, sig)
				if err != nil {
					log.Printf("[ERROR] Failed to create open api spec from template: %v", err)
					return nil, err
				}

				submitted := false
				if status.StateData.ConfigSubmits == nil {
					status.StateData.ConfigSubmits = make(map[string]string)
				}

				// Get current config
				cfgs, err := config.clientServiceMan.Services.Configs.List(ep).Do()
				if err != nil {
					log.Printf("[ERROR] Failed to list current configs for service: %s", ep)
					return nil, err
				}
				if len(cfgs.ServiceConfigs) > 0 {
					cfg := cfgs.ServiceConfigs[0]
					if strings.Contains(cfg.Documentation.Summary, fmt.Sprintf("SIG=%s", sig)) {
						// Configuration already submitted.
						status.Services[host].Config = cfg.Id
						status.StateData.ConfigSubmits[ep] = "NA"
						log.Printf("[INFO] Existing service config for %s found: %s", ep, cfg.Id)
						submitted = true
					}
				}

				if submitted == false {
					log.Printf("[INFO] Submitting endpoint config for: %s", ep)
					configFiles := []*servicemanagement.ConfigFile{
						&servicemanagement.ConfigFile{
							FileContents: base64.StdEncoding.EncodeToString([]byte(openAPISpec)),
							FilePath:     "openapi.yaml",
							FileType:     "OPEN_API_YAML",
						},
					}

					req := servicemanagement.SubmitConfigSourceRequest{
						ValidateOnly: false,
						ConfigSource: &servicemanagement.ConfigSource{
							Files: configFiles,
						},
					}

					op, err := config.clientServiceMan.Services.Configs.Submit(ep, &req).Do()
					if err != nil {
						log.Printf("[ERROR] Failed to submit endpoint config: %v", err)
						return nil, err
					}
					status.StateData.ConfigSubmits[ep] = op.Name
				}
			} else {
				allSubmitted = false
			}
		}
		if allSubmitted {
			nextState = StateEndpointSubmitPending
		}
	}

	if currState == StateEndpointSubmitPending {
		allRolloutsCreated := true
		for host := range hostBackends {
			ep := status.Services[host].Endpoint
			opDone := true
			submitID := status.StateData.ConfigSubmits[ep]
			if submitID != "NA" {
				op, err := config.clientServiceMan.Operations.Get(submitID).Do()
				if err != nil {
					log.Printf("[ERROR] Failed to get service submit operation id: %s", status.StateData.ConfigSubmits[ep])
					return nil, err
				}
				opDone = op.Done

				var resp servicemanagement.SubmitConfigSourceResponse
				data, _ := op.Response.MarshalJSON()
				if err := json.Unmarshal(data, &resp); err != nil {
					log.Printf("[ERROR] Failed to unmarshal submit config response")
					return nil, err
				}
				log.Printf("[INFO] Service config submit complete for endpoint %s, config: %s", ep, resp.ServiceConfig.Id)
				status.Services[host].Config = resp.ServiceConfig.Id
			}

			cfg := status.Services[host].Config

			if opDone {
				found := false

				if status.StateData.ServiceRollouts == nil {
					status.StateData.ServiceRollouts = make(map[string]string)
				}

				resp, err := config.clientServiceMan.Services.Rollouts.List(ep).Do()
				if err != nil {
					log.Printf("[ERROR] Failed to list rollouts for endpoint: %s", ep)
				}
				if len(resp.Rollouts) > 0 {
					if _, ok := resp.Rollouts[0].TrafficPercentStrategy.Percentages[cfg]; ok == true {
						log.Printf("[INFO] Rollout for config already found, skipping rollout for endpoint: %s, config: %s", ep, cfg)
						status.StateData.ServiceRollouts[ep] = "NA"
						found = true
					}
				}

				if found == false {
					// Rollout config
					log.Printf("[INFO] Creating endpoint service config rollout for: endpoint: %s, config: %s", ep, cfg)

					op, err := config.clientServiceMan.Services.Rollouts.Create(ep, &servicemanagement.Rollout{
						TrafficPercentStrategy: &servicemanagement.TrafficPercentStrategy{
							Percentages: map[string]float64{
								cfg: 100.0,
							},
						},
					}).Do()
					if err != nil {
						log.Printf("[ERROR] Failed to create rollout for: endpoint: %s, config: %s", ep, cfg)
						return nil, err
					}
					status.StateData.ServiceRollouts[ep] = op.Name
				}
			} else {
				allRolloutsCreated = false
			}
		}
		if allRolloutsCreated {
			nextState = StateEndpointRolloutPending
		}
	}

	if currState == StateEndpointRolloutPending {
		allRolloutsComplete := true
		for host := range hostBackends {
			ep := status.Services[host].Endpoint
			opName := status.StateData.ServiceRollouts[ep]
			if opName != "NA" {
				op, err := config.clientServiceMan.Operations.Get(opName).Do()
				if err != nil {
					log.Printf("[ERROR] Failed to get rollout operation: %s", opName)
					return nil, err
				}
				if op.Done {
					cfg := status.Services[host].Config
					log.Printf("[INFO] Service config rollout complete for: endpoint: %s, config: %s", ep, cfg)
				} else {
					allRolloutsComplete = false
				}
			}
		}
		if allRolloutsComplete {
			// StateData no longer needed, clear.
			status.StateData = nil

			nextState = StateESPPodPending
		}
	}

	if currState == StateESPPodPending {
		allReady := true
		for host, svcSpec := range hostBackends {
			ep := status.Services[host].Endpoint
			cfg := status.Services[host].Config

			// Create the ConfigMap
			cm, err := makeConfigMap(parent.Namespace, svcSpec.ServiceName, ep, host, cfg)
			if err != nil {
				log.Printf("[ERROR] Failed to create configmap from template for endpoint: %s", ep)
				return nil, err
			}
			desiredChildren = append(desiredChildren, cm)

			if svcSpec.IAP.CreateESP {
				rsName := fmt.Sprintf("%s-esp", svcSpec.ServiceName)

				if _, ok := children.ReplicaSets[rsName]; ok == false {
					// Create the ESP pod.
					if svcSpec.IAP.CreateESP {
						log.Printf("[INFO] Creating ESP pod deployment for: endpoint: %s, config: %s", ep, cfg)

						numReplicas := svcSpec.IAP.ESPReplicas
						if numReplicas == 0 {
							numReplicas = 1 // Default value
						}
						rs, err := makeESPReplicaSet(espContainerImage, parent.Namespace, svcSpec.ServiceName, int(svcSpec.ServicePort.IntVal), host, numReplicas)
						if err != nil {
							log.Printf("[ERROR] Failed to create replicaset from template for endpoint: %s", ep)
							return nil, err
						}
						desiredChildren = append(desiredChildren, rs)
					}
					allReady = false
				} else {
					// ReplicaSet exists, check for if any replicas are Ready.
					rs := children.ReplicaSets[rsName]
					if rs.Status.ReadyReplicas > 0 {
						status.Services[host].ESPPod = "READY"
					} else {
						allReady = false
					}
				}
			} else {
				status.Services[host].ESPPod = "NA"
			}
		}
		if allReady {
			log.Printf("[INFO] All ESP Pods ready.")
			nextState = StateIdle
		}
	}

	// Advance the state
	if status.StateCurrent != nextState {
		log.Printf("[INFO] Current state: %s", nextState)
	}
	status.StateCurrent = nextState

	resp := LambdaResponse{
		Status:   *status,
		Children: desiredChildren,
	}

	return &resp, nil
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}
	return value
}

func makeHostBackends(parent *IapIngress) map[string]*IapIngressBackend {
	res := make(map[string]*IapIngressBackend)
	for _, rule := range parent.Spec.Rules {
		for _, path := range rule.HTTP.Paths {
			res[rule.Host] = &path.Backend
		}
	}
	return res
}

func changeDetected(parent *IapIngress, children *IapIngresControllerRequestChildren, status *IapIngressControllerStatus) bool {
	changed := false

	// If ingress object is deleted, or not yet created, recreating the ingress changes everything.
	if _, ok := children.Ingresses[parent.Name]; status.StateCurrent == StateIdle && ok == false {
		log.Printf("[DEBUG] Changed because ingress not found.")
		changed = true
	}

	// If ESP service, pod, or configmap is deleted, the backend service will be re-created so trigger change.
	for _, svcSpec := range makeHostBackends(parent) {
		espName := fmt.Sprintf("%s-esp", svcSpec.ServiceName)
		if status.StateCurrent == StateIdle {
			if svcSpec.IAP.CreateESP {
				if _, ok := children.Services[espName]; ok == false {
					log.Printf("[DEBUG] Changed because ESP service not found.")
					changed = true
				}
				if _, ok := children.ReplicaSets[espName]; ok == false {
					log.Printf("[DEBUG] Changed because ESP replicaset not found.")
					changed = true
				}
			}
			if _, ok := children.ConfigMaps[espName]; ok == false {
				log.Printf("[DEBUG] Changed because ESP configmap not found.")
				changed = true
			}
		}
	}

	// Mark changed if parent spec changes or ingress backends change from last applied config
	if status.StateCurrent == StateIdle {
		if ing, ok := children.Ingresses[parent.Name]; ok == true {
			if status.LastAppliedSig != calcParentSig(parent, strings.Join(getIngBackends(&ing), ",")) {
				log.Printf("[DEBUG] Changed because parent sig or ingress backends different")
				changed = true
			}
		}
	}

	return changed
}

func calcParentSig(parent *IapIngress, addStr string) string {
	hasher := sha1.New()
	data, err := json.Marshal(&parent.Spec)
	if err != nil {
		log.Printf("[ERROR] Failed to convert parent spec to JSON, this is a bug.")
		return ""
	}
	hasher.Write([]byte(data))
	hasher.Write([]byte(addStr))
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func loadTemplate(name string) (string, error) {
	content, err := ioutil.ReadFile(path.Join(templatePath, name))
	if err != nil {
		return "", nil
	}
	return string(content), nil
}

func getIngBackends(ing *v1beta1.Ingress) []string {
	backends := make([]string, 0)
	if ing == nil {
		return backends
	}
	if b, ok := ing.Annotations["ingress.kubernetes.io/backends"]; ok == true {
		var ingBackendsMap map[string]string
		if err := json.Unmarshal([]byte(b), &ingBackendsMap); err != nil {
			log.Printf("[WARN] Failed to parse ingress.kubernetes.io/backends annotation: %v", err)
			return backends
		}
		for bs := range ingBackendsMap {
			backends = append(backends, bs)
		}
	}
	sort.Strings(backends)
	return backends
}

func makeIngress(parent *IapIngress) *v1beta1.Ingress {
	var ing v1beta1.Ingress
	ing.Kind = "Ingress"
	ing.APIVersion = "extensions/v1beta1"
	ing.ObjectMeta = metav1.ObjectMeta{
		Name:        parent.Name,
		Namespace:   parent.Namespace,
		Annotations: parent.Annotations,
		Labels:      parent.Labels,
	}

	hostBackends := makeHostBackends(parent)

	var rules []v1beta1.IngressRule
	for _, iapRule := range parent.Spec.Rules {
		var paths []v1beta1.HTTPIngressPath
		for _, iapPath := range iapRule.HTTP.Paths {
			// Redirect ingress to ESP service if createESP is false.
			svcName := iapPath.Backend.ServiceName
			svcPort := iapPath.Backend.ServicePort

			if hostBackends[iapRule.Host].IAP.CreateESP {
				svcName = fmt.Sprintf("%s-esp", svcName)
				svcPort = intstr.IntOrString{
					IntVal: int32(80),
					StrVal: "80",
				}
			}

			path := v1beta1.HTTPIngressPath{
				Backend: v1beta1.IngressBackend{
					ServiceName: svcName,
					ServicePort: svcPort,
				},
				Path: iapPath.Path,
			}
			paths = append(paths, path)
		}
		rule := v1beta1.IngressRule{
			Host: iapRule.Host,
		}
		rule.HTTP = &v1beta1.HTTPIngressRuleValue{
			Paths: paths,
		}
		rules = append(rules, rule)
	}
	ing.Spec = v1beta1.IngressSpec{
		Backend: parent.Spec.Backend,
		TLS:     parent.Spec.TLS,
		Rules:   rules,
	}
	return &ing
}

func makeESPService(namespace, serviceName, host string) (*corev1.Service, error) {
	t, err := template.New("esp-svc.yaml").ParseFiles(path.Join(templatePath, "esp-svc.yaml"))
	if err != nil {
		return nil, err
	}

	type espServiceTemplateData struct {
		Namespace   string
		ServiceName string
		Host        string
	}

	data := espServiceTemplateData{
		Namespace:   namespace,
		ServiceName: serviceName,
		Host:        host,
	}

	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return nil, err
	}

	var svc corev1.Service
	if err = yaml.Unmarshal(b.Bytes(), &svc); err != nil {
		return nil, err
	}

	return &svc, nil
}

func makeJWTAudience(projectNum, backendID string) string {
	return fmt.Sprintf("/projects/%s/global/backendServices/%s", projectNum, backendID)
}

func makeOpenAPISig(ep, jwtAud, address string) string {
	sigStr := fmt.Sprintf("%s|%s|%s", ep, jwtAud, address)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(sigStr)))
}

func makeOpenAPI(ep, jwtAud, address, sig string) (string, error) {
	t, err := template.New("openapi.yaml").ParseFiles(path.Join(templatePath, "openapi.yaml"))
	if err != nil {
		return "", err
	}

	type openAPISpecTemplateData struct {
		JWTAudience string
		Endpoint    string
		Address     string
		Signature   string
	}

	data := openAPISpecTemplateData{
		JWTAudience: jwtAud,
		Endpoint:    ep,
		Address:     address,
		Signature:   sig,
	}

	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}

	return b.String(), nil
}

func makeConfigMap(namespace string, svcName string, ep string, host string, cfg string) (*corev1.ConfigMap, error) {
	t, err := template.New("esp-configmap.yaml").ParseFiles(path.Join(templatePath, "esp-configmap.yaml"))
	if err != nil {
		return nil, err
	}

	type espConfigMapTemplateData struct {
		Namespace     string
		ServiceName   string
		Endpoint      string
		ConfigVersion string
		Host          string
	}

	data := espConfigMapTemplateData{
		Namespace:     namespace,
		ServiceName:   svcName,
		Endpoint:      ep,
		ConfigVersion: cfg,
		Host:          host,
	}

	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return nil, err
	}

	var cm corev1.ConfigMap
	if err = yaml.Unmarshal(b.Bytes(), &cm); err != nil {
		return nil, err
	}

	return &cm, nil
}

func makeESPPod(containerImage string, namespace string, svcName string, svcPort int, host string) (*corev1.Pod, error) {
	t, err := template.New("esp-pod.yaml").ParseFiles(path.Join(templatePath, "esp-pod.yaml"))
	if err != nil {
		return nil, err
	}

	type espPodTemplateData struct {
		Namespace      string
		ServiceName    string
		ContainerImage string
		Host           string
		Upstream       string
	}

	data := espPodTemplateData{
		Namespace:      namespace,
		ServiceName:    svcName,
		ContainerImage: containerImage,
		Host:           host,
		Upstream:       fmt.Sprintf("%s:%d", svcName, svcPort),
	}

	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return nil, err
	}

	var pod corev1.Pod
	if err = yaml.Unmarshal(b.Bytes(), &pod); err != nil {
		return nil, err
	}

	return &pod, nil
}

func makeESPReplicaSet(containerImage string, namespace string, svcName string, svcPort int, host string, numReplicas int) (*v1beta1.ReplicaSet, error) {
	t, err := template.New("esp-replicaset.yaml").ParseFiles(path.Join(templatePath, "esp-replicaset.yaml"))
	if err != nil {
		return nil, err
	}

	type espReplicaSetTemplateData struct {
		Namespace      string
		ServiceName    string
		Replicas       int
		ContainerImage string
		Host           string
		Upstream       string
	}

	data := espReplicaSetTemplateData{
		Namespace:      namespace,
		ServiceName:    svcName,
		Replicas:       numReplicas,
		ContainerImage: containerImage,
		Host:           host,
		Upstream:       fmt.Sprintf("%s:%d", svcName, svcPort),
	}

	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return nil, err
	}

	var rs v1beta1.ReplicaSet
	if err = yaml.Unmarshal(b.Bytes(), &rs); err != nil {
		return nil, err
	}

	return &rs, nil
}
