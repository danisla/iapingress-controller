package main

import (
	"fmt"
	"log"
	"strings"
)

func makeStatus(parent *IapIngress, children *IapIngresControllerRequestChildren) *IapIngressControllerStatus {
	status := IapIngressControllerStatus{
		StateCurrent:  "IDLE",
		StateData:     &IapIngressControllerStatusStateData{},
		Address:       "PENDING",
		Authorization: "PENDING",
		NumHosts:      len(parent.Spec.Rules),
		Services:      nil,
	}

	changed := false
	ing := children.Ingresses[parent.Name]
	ingBackends := ""
	if &ing != nil {
		bsList, err := getIngBackendServices(parent, &ing)
		if err != nil {
			log.Printf("[WARN] Failed to get backend services from ingress: %v", err)
		} else {
			ingBackends = strings.Join(bsList, ",")
		}
	}
	sig := calcParentSig(parent, ingBackends)

	if parent.Status.LastAppliedSig != "" {
		if parent.Status.StateCurrent == StateIdle && sig != parent.Status.LastAppliedSig {
			changed = true
			status.LastAppliedSig = ""
		} else {
			status.LastAppliedSig = parent.Status.LastAppliedSig
		}
	}

	if parent.Status.StateCurrent != "" && changed == false {
		status.StateCurrent = parent.Status.StateCurrent
	}
	if parent.Status.StateData != nil && changed == false {
		status.StateData = parent.Status.StateData
	}
	if parent.Status.Address != "" && changed == false {
		status.Address = parent.Status.Address
	}
	if parent.Status.Authorization != "" && changed == false {
		status.Authorization = parent.Status.Authorization
	}
	if parent.Status.NumHosts != 0 && changed == false {
		status.NumHosts = parent.Status.NumHosts
	}
	if parent.Status.Services != nil && changed == false {
		status.Services = parent.Status.Services
	}

	if status.Services == nil && changed == false {
		serviceStatus := make(map[string]*IapIngressControllerStatusServices)
		for host, svcSpec := range makeHostBackends(parent) {
			log.Printf("[INFO] Initializing service status for host: %v", host)
			serviceStatus[host] = makeServiceStatus(host, svcSpec.ServiceName)
		}
		status.Services = serviceStatus
	}

	return &status
}

func makeServiceStatus(host, serviceName string) *IapIngressControllerStatusServices {
	status := IapIngressControllerStatusServices{
		Endpoint:        fmt.Sprintf("%s.endpoints.%s.cloud.goog", serviceName, config.Project),
		RedirectURI:     fmt.Sprintf("https://%s/_gcp_gatekeeper/authenticate", host),
		Backend:         "PENDING",
		Config:          "PENDING",
		IAP:             "PENDING",
		UpstreamService: serviceName,
		ESPPod:          "PENDING",
	}
	return &status
}
