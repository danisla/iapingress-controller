package main

import (
	corev1 "k8s.io/api/core/v1"
	v1beta1 "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// IapIngressControllerState represents the string mapping of the possible controller states. See the const definition below for enumerated states.
type IapIngressControllerState string

const (
	StateIdle                   = "IDLE"
	StateIPPending              = "IP_PENDING"
	StateBackendSvcPending      = "BACKEND_SVC_PENDING"
	StateIAPUpdatePending       = "IAP_UPDATE_PENDING"
	StateEndpointCreatePending  = "ENDPOINT_CREATE_PENDING"
	StateEndpointSubmitPending  = "ENDPOINT_SUBMIT_PENDING"
	StateEndpointRolloutPending = "ENDPOINT_ROLLOUT_PENDING"
	StateESPPodPending          = "ESP_POD_PENDING"
)

// LambdaRequest describes the payload from the LambdaController hook
type LambdaRequest struct {
	Parent   IapIngress                         `json:"parent"`
	Children IapIngresControllerRequestChildren `json:"children"`
}

// LambdaResponse is the LambdaController response structure.
type LambdaResponse struct {
	Status   IapIngressControllerStatus `json:"status`
	Children []interface{}              `json:"children"`
}

// IapIngresControllerRequestChildren is the children definition passed by the LambdaController request for the IapIngress controller.
type IapIngresControllerRequestChildren struct {
	Services    map[string]corev1.Service     `json:"Service.v1"`
	ConfigMaps  map[string]corev1.ConfigMap   `json:"ConfigMap.v1"`
	Ingresses   map[string]v1beta1.Ingress    `json:"Ingress.extensions/v1beta1"`
	ReplicaSets map[string]v1beta1.ReplicaSet `json:"Replicaset.extensions/v1beta1"`
}

// IapIngressControllerStatus is the status structure for the custom resource
type IapIngressControllerStatus struct {
	LastAppliedSig string                                         `json:"lastAppliedSig"`
	StateCurrent   string                                         `json:"stateCurrent"`
	Address        string                                         `json:"address"`
	Authorization  string                                         `json:"authorization"`
	NumHosts       int                                            `json:"numHosts"`
	StateData      *IapIngressControllerStatusStateData           `json:"stateData,omitempty"`
	Services       map[string]*IapIngressControllerStatusServices `json:"services"`
}

// IapIngressControllerStatusStateData is the data structure stored in the StateData.
type IapIngressControllerStatusStateData struct {
	NodePorts       map[string]string                  `json:"nodePorts,omitempty"`
	Backends        map[string]BackendServiceStateData `json:"backends,omitempty"`
	BackendsReady   bool                               `json:"backendsReady,omitempty"`
	ConfigSubmits   map[string]string                  `json:"configSubmits,omitempty"`
	ServiceRollouts map[string]string                  `json:"serviceRollouts,omitempty"`
}

// BackendServiceStateData is the truncated form of the compute.BackendService structure.
type BackendServiceStateData struct {
	Name string `json:"name"`
	ID   string `json:"id"`
	IAP  bool   `json:"iap,omitempty"`
}

// IapIngressControllerStatusServices is the structure for the controller status services
type IapIngressControllerStatusServices struct {
	Endpoint        string `json:"endpoint"`
	RedirectURI     string `json:"redirectUri"`
	Backend         string `json:"backend"`
	Config          string `json:"config"`
	IAP             string `json:"iap"`
	UpstreamService string `json:"upstreamService"`
	ESPPod          string `json:"espPod"`
}

// IapIngress is the custom resource definition structure.
type IapIngress struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              IapIngressSpec             `json:"spec,omitempty"`
	Status            IapIngressControllerStatus `json:"status"`
}

// IapIngressSpec mirrors the IngressSpec with added IAPProjectAuthz spec and a custom Rules spec.
type IapIngressSpec struct {
	IAPProjectAuthz IapProjectAuthzSpec     `json:"iapProjectAuthz"`
	Backend         *v1beta1.IngressBackend `json:"backend,omitempty"`
	TLS             []v1beta1.IngressTLS    `json:"tls,omitempty"`
	Rules           []IapIngressRule        `json:"rules,omitempty"`
}

// IapIngressRule is the customized Rules spec from the IngressRule spec.
type IapIngressRule struct {
	Host string `json:"host,omitempty"`
	// IAP                         IapIngressRuleSpec               `json:"iap,omitempty"`
	HTTP IapIngressHTTPIngressRuleValue `json:"http,omitempty"`
}

// IapProjectAuthzSpec is the spec for the IAPProjectAuthz definition within the IapIngress struct.
type IapProjectAuthzSpec struct {
	Role    string   `json:"role,omitempty"`
	Members []string `json:"members,omitempty"`
}

// IapIngressHTTPIngressRuleValue is the customized structure for the ingress paths spec.
type IapIngressHTTPIngressRuleValue struct {
	Paths []IapIngressHTTPIngressPath `json:"paths"`
}

// IapIngressHTTPIngressPath is the customized structure of the ingress HTTP spec.
type IapIngressHTTPIngressPath struct {
	Path    string            `json:"path,omitempty"`
	Backend IapIngressBackend `json:"backend"`
}

// IapIngressBackend is the custom spec for the HTTP path.
type IapIngressBackend struct {
	ServiceName string                `json:"serviceName"`
	ServicePort intstr.IntOrString    `json:"servicePort"`
	IAP         IapIngressBackendSpec `json:"iap,omitempty"`
}

// IapIngressBackendSpec is the spec for the IAP field in the custom IapIngressRule spec.
type IapIngressBackendSpec struct {
	Enabled         bool   `json:"enabled,omitempty"`
	CreateESP       bool   `json:"createESP,omitempty"`
	ESPReplicas     int    `json:"espReplicas,omitempty"`
	OAuthSecretName string `json:"oauthSecret,omitempty"`
}
