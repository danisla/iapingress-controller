SHELL := /bin/bash

APP := iapingress-controller
CHART_DIR := charts/iapingress-controller
NS := metacontroller
DEPS := $(addprefix $(CHART_DIR)/, oauth.env iapingress-controller-sa-key.json)
GODEV_BUILD_SUBDIR := ./cmd/iapingress-controller
DEVSHELL=bash

NFS_CHART_DIR := charts/nfs-server
NFS_HOST := godev-nfs-nfs-server.$(NS).svc.cluster.local

define get_pod
$(shell kubectl get pods -n $(NS) -l app=$(APP) -o jsonpath='{.items..metadata.name}')
endef

define get_metapod
$(shell kubectl get pods -n $(NS) -l app=kube-metacontroller -o jsonpath='{.items..metadata.name}')
endef

define wait_pod
$(shell while [[ $$(kubectl get pods -n $(NS) -l app=$(APP) -o json | jq -r '.items[] | select(.status.containerStatuses[].ready == true) | .metadata.name' | wc -l) -ne 2 ]]; do \
  echo "Waiting for deployment..." 1>&2; \
  sleep 2; \
done)
endef

install: install-nfs install-chart wait dev-cp deps build

install-nfs:
	(cd $(NFS_CHART_DIR) && \
	helm install --name godev-nfs --namespace=$(NS) .)

install-chart: $(DEPS)
	(cd $(CHART_DIR) && \
	kubectl create secret generic iap-oauth -n $(NS) --from-env-file=oauth.env ; \
	kubectl create secret generic $(APP)-sa -n $(NS) --from-file=$(APP)-sa-key.json ; \
	helm install --name $(APP) --namespace=$(NS) --set godev.enabled=true,godev.persistence.nfsHost=$(NFS_HOST),cloudSA.secretName=$(APP)-sa,cloudSA.secretKey=$(APP)-sa-key.json,oauthSecret=iap-oauth .)

install-chart-prod: $(DEPS)
	(cd $(CHART_DIR) && \
	kubectl create secret generic iap-oauth -n $(NS) --from-env-file=oauth.env ; \
	kubectl create secret generic $(APP)-sa -n $(NS) --from-file=$(APP)-sa-key.json ; \
	helm install --name $(APP) --namespace=$(NS) --set cloudSA.secretName=$(APP)-sa,cloudSA.secretKey=$(APP)-sa-key.json,oauthSecret=iap-oauth .)

uninstall-chart:
	-helm delete --purge $(APP)

reinstall: uninstall-chart install-chart wait dev-cp deps build

upgrade: upgrade-chart wait

upgrade-chart:
	(cd $(CHART_DIR) && \
	helm upgrade $(APP) .)

deps: dev-cp
	@echo "Installing go deps..." && kubectl exec -n $(NS) -c godev -it $(call get_pod) -- bash -c 'cd /go/src/$(APP) && dep ensure'

$(CHART_DIR)/%:
	$(error prerequisite file not found: $@)

wait:
	$(call wait_pod)

dev-cp:
	@POD=$(call get_pod) && echo "Copying ./ to $${POD}:/go/src/$(APP)" && kubectl cp -n $(NS) -c godev ./ $${POD}:/go/src/$(APP)/

build: dev-cp
	@echo "Building $(GODEV_BUILD_SUBDIR)..." && kubectl exec -n $(NS) -c godev -it $(call get_pod) -- bash -c 'cd /go/src/$(APP)/ && go install $(GODEV_BUILD_SUBDIR)'

lpods:
	kubectl get pods -n $(NS)

podlogs:
	kubectl logs -n $(NS) -c $(APP) --tail=100 -f $(call get_pod)

devlogs:
	kubectl logs -n $(NS) -c godev --tail=100 -f $(call get_pod)

metalogs:
	kubectl logs -n $(NS) --tail=100 -f $(call get_metapod)

shell:
	@kubectl exec -n $(NS) -c $(APP) -it $(call get_pod) -- $(DEVSHELL)

devshell:
	@kubectl exec -n $(NS) -c godev -it $(call get_pod) -- $(DEVSHELL)

image:
	gcloud container builds submit --config cloudbuild.yaml .

clean:
	-helm delete --purge $(APP)
	-helm delete --purge godev-nfs
	-kubectl delete secret -n metacontroller iap-oauth
	-kubectl delete secret -n metacontroller $(APP)-sa

include test.mk