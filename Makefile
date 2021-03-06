SHELL := /bin/bash

APP := iapingress-controller
CHART_DIR := charts/iapingress-controller
NS := metacontroller
DEPS := oauth.env
GODEV_PATH := github.com/danisla/iapingress-controller
GODEV_BUILD_SUBDIR := ./cmd/iapingress-controller
DEVSHELL=bash
IMAGE_PROJECT=cloud-solutions-group

NFS_CHART_DIR := charts/nfs-server
NFS_HOST := godev-nfs-nfs-server.$(NS).svc.cluster.local

ACME_URL := https://acme-v01.api.letsencrypt.org/directory

define get_pod
$(shell kubectl get pods -n $(NS) -l app=$(APP) -o jsonpath='{.items..metadata.name}')
endef

define get_metapod
$(shell kubectl get pods -n $(NS) -l app=kube-metacontroller -o jsonpath='{.items..metadata.name}')
endef

define get_certmanagerpod
$(shell kubectl get pods -l app=cert-manager -o jsonpath='{.items..metadata.name}')
endef

define wait_pod
$(shell while [[ $$(kubectl get pods -n $(NS) -l app=$(APP) -o json | jq -r '.items[] | select(.status.containerStatuses[].ready == true) | .metadata.name' | wc -l) -ne 2 ]]; do \
  echo "Waiting for deployment..." 1>&2; \
  sleep 2; \
done)
endef

define ISSUER
apiVersion: certmanager.k8s.io/v1alpha1
kind: Issuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: {{ACME_URL}}
    email: {{ACME_EMAIL}}
    privateKeySecretRef:
      name: letsencrypt-prod
    http01: {}
endef

install: install-nfs install-chart wait dev-cp deps build

export ISSUER
issuer.yaml:
	$(eval ACCOUNT := $(shell gcloud config get-value account))
	@echo "$${ISSUER}" | \
	    sed -e "s|{{ACME_URL}}|$(ACME_URL)|g" \
		    -e "s|{{ACME_EMAIL}}|$(ACCOUNT)|g" \
		> $@

install-cert-manager: issuer.yaml
	helm install --name cert-manager stable/cert-manager
	kubectl apply -f issuer.yaml

install-kube-metacontroller:
	  @helm install --name metacontroller --namespace metacontroller charts/kube-metacontroller

install-nfs:
	(cd $(NFS_CHART_DIR) && \
	helm install --name godev-nfs --namespace=$(NS) .)

install-chart: $(DEPS)
	kubectl create secret generic iap-ingress-oauth --from-env-file=oauth.env ; \
	(cd $(CHART_DIR) && \
	helm install --name $(APP) --namespace=$(NS) --set godev.enabled=true,godev.persistence.nfsHost=$(NFS_HOST) .)

install-chart-prod: $(DEPS)
	kubectl create secret generic iap-ingress-oauth --from-env-file=oauth.env ; \
	(cd $(CHART_DIR) && \
	helm install --name $(APP) --namespace=$(NS) .)

uninstall-chart:
	-helm delete --purge $(APP)

reinstall: uninstall-chart install-chart wait dev-cp deps build

upgrade: upgrade-chart wait

upgrade-chart:
	(cd $(CHART_DIR) && \
	helm upgrade $(APP) .)

deps: dev-cp
	@echo "Installing go deps with dep..." && kubectl exec -n $(NS) -c godev -it $(call get_pod) -- bash -c 'cd /go/src/$(GODEV_PATH) && dep ensure'

$(CHART_DIR)/%:
	$(error prerequisite file not found: $@)

wait:
	$(call wait_pod)

dev-cp:
	$(eval TMP_DIR := /tmp/$(notdir $(shell mktemp -d)))
	@POD=$(call get_pod) && echo "Copying ./ to $${POD}:/go/src/$(GODEV_PATH)/" && kubectl cp -n $(NS) -c godev ./ $${POD}:$(TMP_DIR) && \
	kubectl exec -n $(NS) -c godev -it $${POD} -- bash -c 'mkdir -p /go/src/$(GODEV_PATH) && rsync -ra $(TMP_DIR)/ /go/src/$(GODEV_PATH)/ && rm -rf $(TMP_DIR)'

build: dev-cp
	@echo "Building $(GODEV_BUILD_SUBDIR)..." && kubectl exec -n $(NS) -c godev -it $(call get_pod) -- bash -c 'cd /go/src/$(GODEV_PATH) && go install $(GODEV_BUILD_SUBDIR)'

lpods:
	kubectl get pods -n $(NS)

podlogs:
	kubectl logs -n $(NS) -c $(APP) --tail=100 -f $(call get_pod)

devlogs:
	kubectl logs -n $(NS) -c godev --tail=100 -f $(call get_pod)

metalogs:
	kubectl logs -n $(NS) --tail=100 -f $(call get_metapod)

certlogs:
	kubectl logs --tail=100 -f $(call get_certmanagerpod) -c cert-manager

shell:
	@kubectl exec -n $(NS) -c $(APP) -it $(call get_pod) -- $(DEVSHELL)

devshell:
	@kubectl exec -n $(NS) -c godev -it $(call get_pod) -- $(DEVSHELL)

image:
	gcloud container builds submit --project $(IMAGE_PROJECT) --config cloudbuild.yaml .

clean:
	-helm delete --purge $(APP)
	-helm delete --purge godev-nfs
	-helm delete --purge metacontroller
	-kubectl delete -f issuer.yaml
	-rm -f issuer.yaml
	-helm delete --purge cert-manager
	-kubectl delete secret iap-ingress-oauth letsencrypt-prod iap-ingress-tls

include test.mk