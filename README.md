# IAP Ingress Controller

## THIS IS NOT AN OFFICIAL GOOGLE PRODUCT

## Intro

Implementation of a [LambdaController kube-metacontroller](https://github.com/GoogleCloudPlatform/kube-metacontroller) to automatically configure the [Identity Aware Proxy](https://cloud.google.com/iap/) for GCE type ingress load balancers.

<img src="https://github.com/danisla/iapingress-controller/raw/master/charts/iapingress-controller/diagram.png" width="800px"></img>

This controller utilizes the following major components:
- [cert-manager](https://github.com/kubernetes/charts/tree/master/stable/cert-manager): (optional) Automatically provision SSL certificates for ingress.
- [Custom Resource Definitions (CRD)](https://kubernetes.io/docs/concepts/api-extension/custom-resources/): Used to represent the new `IapIngress` custom resource.
- [kube-metacontroller](https://github.com/GoogleCloudPlatform/kube-metacontroller): Implements the LambdaController interface for the Custom Resource Definition.
- [Extensible Service Proxy (ESP)](https://github.com/cloudendpoints/esp): Nginx based proxy used to verify the [signed IAP headers](https://cloud.google.com/iap/docs/signed-headers-howto) and proxy traffic to your Kubernetes service.

What cannot be automated at this time:
- Management of the OAuth authorized redirect URIs. This must be manually managed from the Cloud Console.

The controller performs the following actions when a new `IapIngress` resource is created:

1. Updates project IAM policy to grant members access to IAP.
2. Creates a new `Ingress` resource.
3. Enables IAP on the backend services.
4. Creates a [Cloud Endpoints service and DNS record](https://cloud.google.com/endpoints/docs/openapi/naming-your-api-service) in the form of `SERVICE.endpoints.PROJECT_ID.cloud.goog`.
5. Deploys a wildcard OpenAPI spec to the Cloud Endpoints service configured for the IAP-enabled backend service.
6. Creates a new `Service` and `Pod` postfixed with `-esp` for the [Extensible Service Proxy](https://github.com/cloudendpoints/esp/blob/master/doc/k8s/README.md) used to verify signed IAP headers in requests.
  a. The backend services route traffic to the ESP `NodePort` service.
  b. The ESP pod has a `readinessProbe` configured to verify that `https://HOSTNAME/_gcp_iap/identity` is responding before registering as a valid endpoint to prevent accidentally exposing your service before IAP is enabled.

## Prerequisites

1. Create GKE cluster:

```
ZONE=us-central1-f
CLUSTER_VERSION=$(gcloud beta container get-server-config --zone ${ZONE} --format='value(validMasterVersions[0])')

gcloud container clusters create dev \
  --cluster-version ${CLUSTER_VERSION} \
  --machine-type n1-standard-4 \
  --num-nodes 6 \
  --scopes=cloud-platform \
  --zone ${ZONE}
```

2. [Install Helm](https://github.com/kubernetes/helm/blob/master/docs/install.md#installing-the-helm-client)
3. Initialize Helm

```
kubectl create serviceaccount tiller --namespace kube-system
kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
helm init --service-account=tiller
```

4. Install cert-manager (optional)

```
helm install \
  --name cert-manager stable/cert-manager \
  --namespace cert-manager

ACME_URL=https://acme-v01.api.letsencrypt.org/directory
ACME_EMAIL=$(gcloud config get-value account)

cat > issuer.yaml <<EOF
apiVersion: certmanager.k8s.io/v1alpha1
kind: Issuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: ${ACME_URL}
    email: ${ACME_EMAIL}
    privateKeySecretRef:
      name: letsencrypt-prod
    http01: {}
EOF

kubectl apply -f issuer.yaml
```

5. Install kube-metacontroller:

```
helm install --name metacontroller --namespace metacontroller charts/kube-metacontroller
```

## Installing the chart

1. Update the IAM roles for the cluster service account:

```
PROJECT=$(gcloud config get-value project)
SA_EMAIL=$(kubectl run -it --rm --restart=Never kube-shell --image google/cloud-sdk:alpine -- bash -c 'curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email')
for role in roles/compute.admin roles/resourcemanager.projectIamAdmin; do
  gcloud projects add-iam-policy-binding \
      $PROJECT --role ${role} --member serviceAccount:$SA_EMAIL
done
```


2. Install this chart:

```
helm install --name iapingress-controller --namespace=metacontroller charts/iapingress-controller
```

## Usage

1. Create secret with your OAuth client info:
  a. Configure the [OAuth consent screen](https://console.cloud.google.com/apis/credentials/consent).
  b. Create a new [OAuth Web Application Credential](https://console.cloud.google.com/apis/credentials) and record the client ID and secret:

```
echo "CLIENT_ID=MY_CLIENT_ID" > oauth.env
echo "CLIENT_SECRET=MY_CLIENT_SECRET" >> oauth.env

kubectl create secret generic iap-ingress-oauth --from-env-file=oauth.env
```

2. Create an IapIngress resouces like the example below:

```yaml
cat > iapingress.yaml <<EOF
apiVersion: ctl.isla.solutions/v1
kind: IapIngress
metadata:
  name: iap-ingress
  annotations:
    certmanager.k8s.io/issuer: "letsencrypt-prod"
    certmanager.k8s.io/acme-challenge-type: "http01"
    ingress.kubernetes.io/ssl-redirect: "true"
    kubernetes.io/ingress.class: "gce"
spec:
  iapProjectAuthz:
    role: "roles/iap.httpsResourceAccessor"
    members:
    - "user:MY_ACCOUNT"
  tls:
  - secretName: "iap-ingress-tls"
    hosts:
    - service1.endpoints.MY_PROJECT.cloud.goog
    - service2.mydomain
  rules:
  - host: service1.MY_PROJECT.cloud.goog
    http:
      paths:
      - path:
        backend:
          iap:
            enabled: true
            createESP: true
            oauthSecret: iap-ingress-oauth
          serviceName: service1
          servicePort: 80
  - host: service2.mydomain
    http:
      paths:
      - path:
        backend:
          iap:
            enabled: true
            createESP: true
          serviceName: service2
          servicePort: 80
EOF

kubectl apply -f iapingress.yaml
```

1. Add authorized users to the `iapProjectAuthz.members` list.
2. If you are using the provided `*.cloud.goog` DNS records, set the values of the services entries appropriately and replace `MY_PROJECT` with the project id of your Google Cloud Platform project.
  a. If you are not using not the provided `*.cloud.goog` record) then create a CNAME record that points to the `SERVICE.endpoints.MY_PROJECT.cloud.goog` record.
3. Enable IAP for each rule http path by setting `path.backend.iap.enabled` to `true`.
4. Add each of your endpoints to the authorized redirect uris for your OAuth 2.0 Client ID config:
  a. Open the OAuth 2.0 Client ID config for your credential: https://console.cloud.google.com/apis/credentials
  b. Add redirect URIs for each of your hosts in the form of: `https://HOSTNAME/_gcp_gatekeeper/authenticate`
  c. NOTE: You can also run `kubectl describe iaping iap-ingress` to see the redirect uris.

Example kubectl commands:

```
  kubectl get iaping

  kubectl describe iaping iap-ingress

  kubectl delete iaping iap-ingress
```