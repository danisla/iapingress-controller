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
	"os/exec"
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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
)

var (
	config                       Config
	templatePath                 string
	defaultIAMRole               string
	espContainerImage            string
	defaultESPIngressServicePort intstr.IntOrString
	defaultTimeoutSec            intstr.IntOrString
)

func init() {
	templatePath = getenv("TEMPLATE_PATH", "/opt/app")
	defaultIAMRole = getenv("DEFAULT_IAM_ROLE", "roles/iap.httpsResourceAccessor")
	espContainerImage = getenv("ESP_CONTAINER_IMAGE", "gcr.io/endpoints-release/endpoints-runtime:1")

	defaultESPIngressServicePort = intstr.IntOrString{
		IntVal: int32(8080),
		StrVal: "8080",
	}

	defaultTimeoutSec = intstr.IntOrString{
		IntVal: int32(30),
		StrVal: "30",
	}

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

		desiredStatus, desiredChildren, err := sync(&req.Parent, &req.Children)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("[ERROR] Could not sync state: %v", err)
		}

		resp := LambdaResponse{
			Status:   *desiredStatus,
			Children: *desiredChildren,
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

func sync(parent *IapIngress, children *IapIngresControllerRequestChildren) (*IapIngressControllerStatus, *[]interface{}, error) {
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
			return status, &desiredChildren, err
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
			return status, &desiredChildren, err
		}

		status.Authorization = fmt.Sprintf("%d members", len(members))

		// Create the default backend for the ingress
		log.Printf("[INFO] Creating default backend")
		beRs, err := makeESPDefaultBackendReplicaSet(parent.Namespace)
		if err != nil {
			log.Printf("[ERROR] Failed to create default ESP backend replicaset resource from template: %v", err)
			return status, &desiredChildren, err
		}
		desiredChildren = append(desiredChildren, beRs)

		beSvc, err := makeESPDefaultBackendService(parent.Namespace)
		if err != nil {
			log.Printf("[ERROR] Failed to create default ESP backend service resource from template: %v", err)
			return status, &desiredChildren, err
		}
		desiredChildren = append(desiredChildren, beSvc)

		// Create the Kuberntes Ingress resource
		newIng := makeIngress(parent)
		if _, ok := children.Ingresses[parent.Name]; ok == true {
			log.Printf("[INFO] Updating existing Ingress: %s", newIng.Name)
			// shell exec 'kubectl apply' to update the ingress config.
			// Do this until we can do an apply from the go client. Reference: https://github.com/kubernetes/kubernetes/issues/17333

			if err := kubectlApplyConfig(newIng); err != nil {
				log.Printf("[ERROR] Failed to execute kubectl apply on ingress spec.")
				return status, &desiredChildren, err
			}

		} else {
			log.Printf("[INFO] Creating new Ingress: %s", parent.Name)
		}
		desiredChildren = append(desiredChildren, newIng)

		// Create the ESP service for each host
		for host, svcSpec := range hostBackends {
			if svcSpec.IAP.CreateESP {
				espName := fmt.Sprintf("%s-esp", svcSpec.ServiceName)
				newSvc := makeESPService(parent.Namespace, svcSpec.ServiceName, host)
				if _, ok := children.Services[espName]; ok == true {
					log.Printf("[INFO] Updating existing ESP service: %s", espName)
					if err := kubectlApplyConfig(newSvc); err != nil {
						log.Printf("[ERROR] Failed to execute kubectl apply on ESP service spec.")
						return status, &desiredChildren, err
					}
				} else {
					// Set service selector to match on default-esp-backend while the LB is configured.
					// The ports and health check path for the default backend are the same as the actual ESP service.
					newSvc.Spec.Selector["app"] = "default-esp-backend"

					log.Printf("[INFO] Creating ESP Service: %s", espName)
				}
				desiredChildren = append(desiredChildren, newSvc)

			} else {
				// Lookup existing service
				svc, err := config.clientset.CoreV1().Services(parent.Namespace).Get(svcSpec.ServiceName, metav1.GetOptions{})
				if err != nil {
					log.Printf("[ERROR] Existing service not found: %s", svcSpec.ServiceName)
					return status, &desiredChildren, err
				}
				if svc.Spec.Type != corev1.ServiceTypeNodePort {
					log.Printf("[ERROR] Existing service is not type=NodePort, service: %s, type: %s", svc.Namespace, svc.Spec.Type)
					return status, &desiredChildren, err
				}
				if status.StateData.NodePorts == nil {
					status.StateData.NodePorts = make(map[string]string)
				}
				status.StateData.NodePorts[host] = strconv.Itoa(int(svc.Spec.Ports[0].NodePort))
			}
		}

		nextState = StateIPPending
	} else {
		// Claim the ingress.
		if ing, ok := children.Ingresses[parent.Name]; ok == true {
			desiredChildren = append(desiredChildren, ing)
		}

		// Claim the default backend replicaset and service.
		if beRs, ok := children.ReplicaSets["default-esp-backend"]; ok == true {
			desiredChildren = append(desiredChildren, beRs)
		}
		if beSvc, ok := children.Services["default-esp-backend"]; ok == true {
			desiredChildren = append(desiredChildren, beSvc)
		}

		// Claim the ESP services.
		for _, svcSpec := range hostBackends {
			espName := fmt.Sprintf("%s-esp", svcSpec.ServiceName)
			if svc, ok := children.Services[espName]; ok == true {
				desiredChildren = append(desiredChildren, svc)
			}
		}
	}

	// Claim the ESP services, replicasets and configmaps
	for _, svcSpec := range hostBackends {
		espName := fmt.Sprintf("%s-esp", svcSpec.ServiceName)
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
		} else {
			log.Printf("[WARN] In IP_PENDING status but Ingress child not claimed.")
			nextState = "IDLE"
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
					if svc, ok := children.Services[svcName]; ok == true {
						nodePort = strconv.Itoa(int(svc.Spec.Ports[0].NodePort))
					} else {
						err := fmt.Errorf("[ERROR] Failed to find ESP service: %s", svcName)
						return status, &desiredChildren, err
					}
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
			return status, &desiredChildren, err
		}

		backendPattern, err := regexp.Compile(fmt.Sprintf("(%s)", strings.Join(svcBackendNames, "|")))
		if err != nil {
			log.Printf("[ERROR] Failed to compile backend pattern: %v", err)
			return status, &desiredChildren, err
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

				timeoutSec := int64(defaultTimeoutSec.IntVal)
				if hostBackends[host].TimeoutSec.IntVal > 0 {
					timeoutSec = int64(hostBackends[host].TimeoutSec.IntVal)
				}

				log.Printf("[DEBUG] Setting backend service timeout to: %v", timeoutSec)

				var bsPatch *compute.BackendService

				if hostBackends[host].IAP.Enabled {
					log.Printf("[INFO] Enabling IAP on backend service: %s", backend.Name)

					// Fetch OAuth secret
					secretName := hostBackends[host].IAP.OAuthSecretName
					if secretName == "" {
						log.Printf("[WARN] Missing oauthSecret in parent spec for host: %s", host)
						return status, &desiredChildren, nil
					}

					secret, err := config.clientset.CoreV1().Secrets(parent.Namespace).Get(secretName, metav1.GetOptions{})
					if err != nil {
						log.Printf("[WARN] Failed to get secret for oauthSecret '%s' for host: '%s'", secretName, host)
						return status, &desiredChildren, err
					}

					clientID := string(secret.Data["CLIENT_ID"])
					clientSecret := string(secret.Data["CLIENT_SECRET"])

					if clientID == "" || clientSecret == "" {
						log.Printf("[ERROR] Invalid CLIENT_ID and CLIENT_SECRET found in oauthSecret: %s", secretName)
						return status, &desiredChildren, nil
					}

					secretSha256 := fmt.Sprintf("%x", sha256.Sum256([]byte(clientSecret)))
					bsPatch = &compute.BackendService{
						TimeoutSec: timeoutSec,
						Iap: &compute.BackendServiceIAP{
							Enabled:                  true,
							Oauth2ClientId:           clientID,
							Oauth2ClientSecret:       clientSecret,
							Oauth2ClientSecretSha256: secretSha256,
						},
					}
				} else {
					log.Printf("[INFO] Disabling IAP on backend service: %s", backend.Name)

					bsPatch = &compute.BackendService{
						TimeoutSec: timeoutSec,
						Iap: &compute.BackendServiceIAP{
							Enabled: false,
						},
					}
					status.Services[host].IAP = "Disabled"
				}

				_, err = config.clientCompute.BackendServices.Patch(config.Project, backend.Name, bsPatch).Do()
				if err != nil {
					log.Printf("[WARN] Error when updating IAP on backend: %s: %v", backend.Name, err)
				}
			}
			nextState = StateIAPUpdatePending

			log.Printf("[INFO] All ingress backends are ready")

			if ing, ok := children.Ingresses[parent.Name]; ok == true {
				ingBackends := ""
				bsList, err := getIngBackendServices(parent, &ing)
				if err != nil {
					log.Printf("[WARN] Failed to get backend services from ingress: %v", err)
				} else {
					ingBackends = strings.Join(bsList, ",")
				}
				status.LastAppliedSig = calcParentSig(parent, ingBackends)
			}
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
					return status, &desiredChildren, err
				}

				submitted := false
				if status.StateData.ConfigSubmits == nil {
					status.StateData.ConfigSubmits = make(map[string]string)
				}

				// Get current config
				cfgs, err := config.clientServiceMan.Services.Configs.List(ep).Do()
				if err != nil {
					log.Printf("[ERROR] Failed to list current configs for service: %s", ep)
					return status, &desiredChildren, err
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
						return status, &desiredChildren, err
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
					return status, &desiredChildren, err
				}
				opDone = op.Done

				var r servicemanagement.SubmitConfigSourceResponse
				data, _ := op.Response.MarshalJSON()
				if err := json.Unmarshal(data, &r); err != nil {
					log.Printf("[ERROR] Failed to unmarshal submit config response")
					return status, &desiredChildren, err
				}
				log.Printf("[INFO] Service config submit complete for endpoint %s, config: %s", ep, r.ServiceConfig.Id)
				status.Services[host].Config = r.ServiceConfig.Id
			}

			cfg := status.Services[host].Config

			if opDone {
				found := false

				if status.StateData.ServiceRollouts == nil {
					status.StateData.ServiceRollouts = make(map[string]string)
				}

				r, err := config.clientServiceMan.Services.Rollouts.List(ep).Do()
				if err != nil {
					log.Printf("[ERROR] Failed to list rollouts for endpoint: %s", ep)
				}
				if len(r.Rollouts) > 0 {
					if _, ok := r.Rollouts[0].TrafficPercentStrategy.Percentages[cfg]; ok == true {
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
						return status, &desiredChildren, err
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
					return status, &desiredChildren, err
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
			for host, svcSpec := range hostBackends {
				ep := status.Services[host].Endpoint
				cfg := status.Services[host].Config

				// Create the ConfigMap

				// Custom nginx config template to support websockets until this is resolved: https://github.com/cloudendpoints/endpoints-tools/issues/41
				nginxConfBytes, err := ioutil.ReadFile(path.Join(templatePath, "nginx-auto.conf.template"))
				if err != nil {
					log.Printf("[ERROR] Failed to ready nginx conf template file")
					return status, &desiredChildren, err
				}
				nginxConfB64 := base64.StdEncoding.EncodeToString(nginxConfBytes)

				cm := makeConfigMap(parent.Namespace, svcSpec.ServiceName, ep, cfg, nginxConfB64)
				if _, ok := children.ConfigMaps[cm.Name]; ok == true {
					log.Printf("[INFO] Updating existing ESP configmap: %s", cm.Name)
					if err := kubectlApplyConfig(cm); err != nil {
						log.Printf("[ERROR] Failed to execute kubectl apply on ESP configmap spec.")
						return status, &desiredChildren, err
					}
				}
				if _, ok := children.ConfigMaps[cm.Name]; ok == false {
					desiredChildren = append(desiredChildren, cm)
				}
			}

			nextState = StateESPPodPending
		}
	}

	if currState == StateESPPodPending {
		allReady := true
		for host, svcSpec := range hostBackends {
			ep := status.Services[host].Endpoint
			cfg := status.Services[host].Config

			if svcSpec.IAP.CreateESP {
				rsName := fmt.Sprintf("%s-esp", svcSpec.ServiceName)

				if _, ok := children.ReplicaSets[rsName]; ok == false {
					// Create the ESP pod.
					log.Printf("[INFO] Creating ESP pod deployment for: endpoint: %s, config: %s", ep, cfg)

					// Create hash of configmap to trigger change
					cm := children.ConfigMaps[rsName]
					cmHash, err := makeConfigMapSig(&cm)
					if err != nil {
						log.Printf("[ERROR] Failed to create configmap hash for %s", cm.Name)
						return status, &desiredChildren, err
					}

					numReplicas := svcSpec.IAP.ESPReplicas
					if numReplicas == 0 {
						numReplicas = 1 // Default value
					}
					rs, err := makeESPReplicaSet(espContainerImage, parent.Namespace, svcSpec.ServiceName, int(svcSpec.ServicePort.IntVal), host, numReplicas, cmHash)
					if err != nil {
						log.Printf("[ERROR] Failed to create replicaset from template for endpoint: %s", ep)
						return status, &desiredChildren, err
					}

					if _, ok := children.ReplicaSets[rs.Name]; ok == true {
						log.Printf("[INFO] Updating existing ESP replicaset: %s", cm.Name)
						if err := kubectlApplyConfig(rs); err != nil {
							log.Printf("[ERROR] Failed to execute kubectl apply on ESP replicaset spec.")
							return status, &desiredChildren, err
						}
					}
					desiredChildren = append(desiredChildren, rs)

					// Update the ESP service to point to the pod.
					svc, err := config.clientset.CoreV1().Services(parent.Namespace).Get(rsName, metav1.GetOptions{})
					if err != nil {
						log.Printf("[ERROR] Existing ESP service not found: %s", svcSpec.ServiceName)
						return status, &desiredChildren, err
					}

					oldData, err := json.Marshal(svc)
					if err != nil {
						return status, &desiredChildren, err
					}

					newSvc := svc.DeepCopy()
					newSvc.Spec.Selector["app"] = rsName

					newData, err := json.Marshal(newSvc)
					if err != nil {
						return status, &desiredChildren, err
					}

					patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldData, newData, corev1.Service{})
					if err != nil {
						return status, &desiredChildren, err
					}

					// Patch the original service
					log.Printf("[INFO] Patching service %s to point to app %s", svc.Name, rsName)
					_, err = config.clientset.CoreV1().Services(parent.Namespace).Patch(svc.Name, types.StrategicMergePatchType, patchBytes)
					if err != nil {
						return status, &desiredChildren, err
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

	return status, &desiredChildren, nil
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
			ingBackends := ""
			bsList, err := getIngBackendServices(parent, &ing)
			if err != nil {
				log.Printf("[WARN] Failed to get backend services from ingress")
			} else {
				ingBackends = strings.Join(bsList, ",")
			}
			if status.LastAppliedSig != calcParentSig(parent, ingBackends) {
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

func getIngBackendServices(parent *IapIngress, ing *v1beta1.Ingress) ([]string, error) {
	bsList := make([]string, 0)
	ingBackends := getIngBackends(ing)

	for _, bsName := range ingBackends {
		// Match backend with services.
		for _, rule := range parent.Spec.Rules {
			for _, path := range rule.HTTP.Paths {
				var svcName string
				if path.Backend.IAP.Enabled {
					if path.Backend.IAP.CreateESP {
						svcName = fmt.Sprintf("%s-esp", path.Backend.ServiceName)
					} else {
						svcName = path.Backend.ServiceName
					}
					svc, err := config.clientset.CoreV1().Services(parent.Namespace).Get(svcName, metav1.GetOptions{})
					if err != nil {
						return bsList, err
					}
					if svc.Spec.Type != corev1.ServiceTypeNodePort {
						return bsList, fmt.Errorf("[ERROR] Service is not type=NodePort, service: %s, type: %s", svc.Name, svc.Spec.Type)
					}
					if strings.Contains(bsName, fmt.Sprintf("k8s-be-%s", strconv.Itoa(int(svc.Spec.Ports[0].NodePort)))) {
						bsList = append(bsList, bsName)
					}
				}
			}
		}
	}
	sort.Strings(bsList)
	return bsList, nil
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
				svcPort = defaultESPIngressServicePort
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

func makeESPDefaultBackendReplicaSet(namespace string) (*v1beta1.ReplicaSet, error) {
	t, err := template.New("default-esp-backend.yaml").ParseFiles(path.Join(templatePath, "default-esp-backend.yaml"))
	if err != nil {
		return nil, err
	}

	type espDefaultBackendTemplateData struct {
		Namespace string
	}

	data := espDefaultBackendTemplateData{
		Namespace: namespace,
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

func makeESPDefaultBackendService(namespace string) (*corev1.Service, error) {
	t, err := template.New("default-esp-backend-svc.yaml").ParseFiles(path.Join(templatePath, "default-esp-backend-svc.yaml"))
	if err != nil {
		return nil, err
	}

	type espDefaultBackendServiceTemplateData struct {
		Namespace string
	}

	data := espDefaultBackendServiceTemplateData{
		Namespace: namespace,
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
func makeESPService(namespace, serviceName, host string) *corev1.Service {
	espName := fmt.Sprintf("%s-esp", serviceName)
	var svc corev1.Service
	svc.Kind = "Service"
	svc.APIVersion = "v1"
	svc.ObjectMeta = metav1.ObjectMeta{
		Name:      espName,
		Namespace: namespace,
		Annotations: map[string]string{
			"iapingresses.ctl.isla.solutions/host": host,
		},
	}
	var spec corev1.ServiceSpec
	ports := []corev1.ServicePort{
		corev1.ServicePort{
			Name:       "http",
			Port:       defaultESPIngressServicePort.IntVal,
			TargetPort: defaultESPIngressServicePort,
			Protocol:   corev1.ProtocolTCP,
		},
	}
	spec.Ports = ports
	spec.Selector = map[string]string{
		"app": espName,
	}
	spec.Type = corev1.ServiceTypeNodePort
	svc.Spec = spec

	return &svc
}

func makeJWTAudience(projectNum, backendID string) string {
	return fmt.Sprintf("/projects/%s/global/backendServices/%s", projectNum, backendID)
}

func makeOpenAPISig(ep, jwtAud, address string) string {
	sigStr := fmt.Sprintf("%s|%s|%s", ep, jwtAud, address)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(sigStr)))
}

func makeConfigMapSig(cm *corev1.ConfigMap) (string, error) {
	data, err := json.Marshal(&cm)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(string(data)))), nil
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

func makeConfigMap(namespace string, serviceName string, ep string, cfg string, nginxConf string) *corev1.ConfigMap {
	espName := fmt.Sprintf("%s-esp", serviceName)

	var cm corev1.ConfigMap
	cm.Kind = "ConfigMap"
	cm.APIVersion = "v1"
	cm.ObjectMeta = metav1.ObjectMeta{
		Name:      espName,
		Namespace: namespace,
		Labels: map[string]string{
			"app": espName,
		},
	}

	cm.Data = map[string]string{
		"ENDPOINT":                 ep,
		"CONFIG_VERSION":           cfg,
		"nginx-auto.conf.template": nginxConf,
	}

	return &cm
}

func makeESPReplicaSet(containerImage string, namespace string, svcName string, svcPort int, host string, numReplicas int, cmHash string) (*v1beta1.ReplicaSet, error) {
	t, err := template.New("esp-replicaset.yaml").ParseFiles(path.Join(templatePath, "esp-replicaset.yaml"))
	if err != nil {
		return nil, err
	}

	type espReplicaSetTemplateData struct {
		Namespace      string
		ConfigMapHash  string
		ServiceName    string
		Replicas       int
		ContainerImage string
		Host           string
		Upstream       string
	}

	data := espReplicaSetTemplateData{
		Namespace:      namespace,
		ConfigMapHash:  cmHash,
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

func kubectlApplyConfig(o interface{}) error {
	data, err := json.Marshal(&o)
	if err != nil {
		return err
	}

	cmd := exec.Command("kubectl", "apply", "-f", "-")
	stdout := &bytes.Buffer{}
	cmd.Stdout = stdout
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	cmd.Stdin = strings.NewReader(string(data))

	err = cmd.Run()
	if err != nil {
		log.Printf("[DEBUG] kubectl apply output: %s %s", stdout.String(), stderr.String())
	}

	return err
}
