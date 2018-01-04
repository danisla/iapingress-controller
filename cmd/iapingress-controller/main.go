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
	status := makeStatus(parent)
	currState := status.StateCurrent
	if currState == "" {
		currState = "IDLE"
	}
	desiredChildren := make([]interface{}, 0)
	nextState := currState[0:1] + currState[1:] // string copy of currState

	changed := changeDetected(parent, children, status)
	if changed {
		log.Printf("[INFO] Change in spec detected, restarting state machine.")
	}

	hostBackends := makeHostBackends(parent)

	if currState == "IDLE" && changed {
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
			}
		}

		status.LastAppliedSig = calcParentSig(parent)
		nextState = "IP_PENDING"
	} else {
		// Claim the ingress.
		if ing, ok := children.Ingresses[parent.Name]; ok == true {
			desiredChildren = append(desiredChildren, ing)
		}

		// Claim the ESP services and pods.
		for _, svcSpec := range hostBackends {
			espName := fmt.Sprintf("%s-esp", svcSpec.ServiceName)
			if svc, ok := children.Services[espName]; ok == true {
				desiredChildren = append(desiredChildren, svc)
			}
			if pod, ok := children.Pods[espName]; ok == true {
				desiredChildren = append(desiredChildren, pod)
			}
		}
	}

	if currState == "IP_PENDING" {
		if ing, ok := children.Ingresses[parent.Name]; ok == true {
			if len(ing.Status.LoadBalancer.Ingress) > 0 {
				if ing.Status.LoadBalancer.Ingress[0].IP != "" {
					status.Address = ing.Status.LoadBalancer.Ingress[0].IP
					log.Printf("[INFO] Ingress IP found: %s", status.Address)
					nextState = "BACKEND_SVC_PENDING"
				}
			}
		}
	}

	if currState == "BACKEND_SVC_PENDING" || currState == "IAP_ENABLE_PENDING" {
		// Get list of backends created by the GCE ingress controller.
		var svcBackendNames []string
		if b, ok := children.Ingresses[parent.Name].Annotations["ingress.kubernetes.io/backends"]; ok == true {
			var ingBackendsMap map[string]string
			if err := json.Unmarshal([]byte(b), &ingBackendsMap); err != nil {
				log.Printf("[ERROR] Failed to parse ingress.kubernetes.io/backends annotation: %v", err)
				return nil, err
			}
			for bsName := range ingBackendsMap {
				// Match backend with services.
				for host, svcSpec := range hostBackends {
					svcName := fmt.Sprintf("%s-esp", svcSpec.ServiceName)
					nodePort := strconv.Itoa(int(children.Services[svcName].Spec.Ports[0].NodePort))
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
			nodePort := strconv.Itoa(int(children.Services[svcName].Spec.Ports[0].NodePort))
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
			// Enable IAP on the backends
			for host, backend := range backendServicesMap {
				if hostBackends[host].IAP.Enabled && (backend.Iap == nil || backend.Iap.Enabled == false) {
					log.Printf("[INFO] Enabling IAP on backend service: %s", backend.Name)
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
						log.Printf("[WARN] Error when enabling IAP on backend: %s: %v", backend.Name, err)
					}
				}
			}
			nextState = "IAP_ENABLE_PENDING"
		}

		if currState == "IAP_ENABLE_PENDING" {
			// Wait for IAP enable to complete
			allEnabled := true
			for host, backend := range status.StateData.Backends {
				if hostBackends[host].IAP.Enabled == false {
					continue
				}
				if backend.IAP == true {
					log.Printf("[INFO] IAP enabled on backend: %s", backend.Name)
					status.Services[host].IAP = "Enabled"
				} else {
					allEnabled = false
				}
			}
			if allEnabled {
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
				nextState = "ENDPOINT_CREATE_PENDING"
			}
		}
	}

	if currState == "ENDPOINT_CREATE_PENDING" {
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
			nextState = "ENDPOINT_SUBMIT_PENDING"
		}
	}

	if currState == "ENDPOINT_SUBMIT_PENDING" {
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
			nextState = "ENDPOINT_ROLLOUT_PENDING"
		}
	}

	if currState == "ENDPOINT_ROLLOUT_PENDING" {
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

			nextState = "ESP_POD_PENDING"
		}
	}

	if currState == "ESP_POD_PENDING" {
		allReady := true
		for host, svcSpec := range hostBackends {
			if svcSpec.IAP.CreateESP {
				podName := fmt.Sprintf("%s-esp", svcSpec.ServiceName)

				if _, ok := children.Pods[podName]; ok == false {
					// Create the ESP pod.
					ep := status.Services[host].Endpoint
					cfg := status.Services[host].Config
					if svcSpec.IAP.CreateESP {
						log.Printf("[INFO] Creating ESP pod deployment for: endpoint: %s, config: %s", ep, cfg)

						pod, err := makeESPPod(espContainerImage, parent.Namespace, svcSpec.ServiceName, int(svcSpec.ServicePort.IntVal), ep, host, cfg)
						if err != nil {
							fmt.Printf("[ERROR] Failed to create pod from template for endpoint: %s", ep)
							return nil, err
						}
						desiredChildren = append(desiredChildren, pod)
					}
				} else {
					// Pod exists, check for Ready state
					if len(children.Pods[podName].Status.Conditions) == 0 {
						allReady = false
					}
					for _, c := range children.Pods[podName].Status.Conditions {
						if c.Type == corev1.PodReady {
							if c.Status == corev1.ConditionTrue {
								status.Services[host].ESPPod = "READY"
							} else {
								allReady = false
							}
						}
					}
				}
			} else {
				status.Services[host].ESPPod = "NA"
			}
		}
		if allReady {
			log.Printf("[INFO] All ESP Pods ready.")
			nextState = "IDLE"
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
	if _, ok := children.Ingresses[parent.Name]; ok == false {
		changed = true
	}

	// If ESP service or pod is deleted, the backend service will be re-created so trigger change.
	for _, svcSpec := range makeHostBackends(parent) {
		espName := fmt.Sprintf("%s-esp", svcSpec.ServiceName)
		if _, ok := children.Services[espName]; ok == false && status.StateCurrent == "IDLE" {
			changed = true
		}
		if _, ok := children.Pods[espName]; ok == false && status.StateCurrent == "IDLE" {
			changed = true
		}
	}

	// Mark changed if parent spec changes from last applied config
	if status.LastAppliedSig != calcParentSig(parent) {
		changed = true
	}

	return changed
}

func calcParentSig(parent *IapIngress) string {
	hasher := sha1.New()
	data, ok := parent.Annotations["kubectl.kubernetes.io/last-applied-configuration"]
	if ok == false || data == "" {
		log.Printf("[WARN] Parent spec annotation kubectl.kubernetes.io/last-applied-configuration was empty")
	}
	hasher.Write([]byte(data))
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func loadTemplate(name string) (string, error) {
	content, err := ioutil.ReadFile(path.Join(templatePath, name))
	if err != nil {
		return "", nil
	}
	return string(content), nil
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

func makeESPPod(containerImage string, namespace string, svcName string, svcPort int, ep string, host string, cfg string) (*corev1.Pod, error) {
	t, err := template.New("esp-pod.yaml").ParseFiles(path.Join(templatePath, "esp-pod.yaml"))
	if err != nil {
		return nil, err
	}

	type espPodTemplateData struct {
		ContainerImage string
		Namespace      string
		ServiceName    string
		Endpoint       string
		ConfigVersion  string
		Host           string
		Upstream       string
	}

	data := espPodTemplateData{
		ContainerImage: containerImage,
		Namespace:      namespace,
		ServiceName:    svcName,
		Endpoint:       ep,
		ConfigVersion:  cfg,
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
