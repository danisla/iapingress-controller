
TEST_ARTIFACTS := iapingress.yaml service1.yaml service2.yaml

define TEST_IAPINGRESS
apiVersion: ctl.isla.solutions/v1
kind: IapIngress
metadata:
  name: iap-ingress
  annotations:
    kubernetes.io/tls-acme: "true"
    ingress.kubernetes.io/ssl-redirect: "true"
    kubernetes.io/ingress.class: "gce"
spec:
  iapProjectAuthz:
    role: "roles/iap.httpsResourceAccessor"
    members:
    - "user:{{ACCOUNT}}"
  tls:
  - secretName: "iap-ingress-tls"
    hosts:
    - service1.endpoints.{{PROJECT}}.cloud.goog
    - service2.endpoints.{{PROJECT}}.cloud.goog
  rules:
  - host: service1.endpoints.{{PROJECT}}.cloud.goog
    http:
      paths:
      - path:
        backend:
          iap:
            enabled: true
            createESP: true
          serviceName: service1
          servicePort: 80
  - host: service2.endpoints.{{PROJECT}}.cloud.goog
    http:
      paths:
      - path:
        backend:
          iap:
            enabled: true
            createESP: true
          serviceName: service2
          servicePort: 80
endef

define TEST_SERVICE
apiVersion: v1
kind: Service
metadata:
  name: {{NAME}}
spec:
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
    name: http
  selector:
    app: {{NAME}}
  type: ClusterIP
---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: {{NAME}}
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: {{NAME}}
    spec:
      containers:
      - name: app
        image: python:3-slim
        command:
        - python3
        - "-c"
        - |
          from http.server import HTTPServer, BaseHTTPRequestHandler
          PORT=8080
          class RequestHandler(BaseHTTPRequestHandler):
              def do_GET(self):
                  self.send_response(200)
                  self.send_header('Content-type','text/html')
                  self.end_headers()
                  self.wfile.write(bytes("""
                  <!doctype html><html>
                <head><title>IAP Tutorial</title><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/materialize/0.100.2/css/materialize.min.css"></head>
                <body>
                <div class="container">
                <div class="row">
                <div class="col s2">&nbsp;</div>
                <div class="col s8">
                <div class="card blue">
                    <div class="card-content white-text">
                        <h4>Hello %s</h4>
                    </div>
                    <div class="card-action">
                        <a href="/_gcp_iap/identity">Identity JSON</a>
                        <a href="/_gcp_iap/clear_login_cookie">Logout</a>
                    </div>
                </div></div></div></div>
                </body></html>
                  """ % self.headers.get("x-goog-authenticated-user-email","unauthenticated user").split(':')[-1], "utf8"))
          print("Listing on port", PORT)
          server = HTTPServer(('0.0.0.0', PORT), RequestHandler)
          server.serve_forever()
        ports:
          - containerPort: 8080
        readinessProbe:
          httpGet:
            path: /
            port: 8080
            scheme: HTTP
          periodSeconds: 10
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 2
endef

export TEST_IAPINGRESS
iapingress.yaml:
	@PROJECT=$$(gcloud config get-value project) ACCOUNT=$$(gcloud config get-value account) && \
	  echo "$${TEST_IAPINGRESS}" | \
	    sed -e "s/{{PROJECT}}/$${PROJECT}/g" \
		    -e "s/{{ACCOUNT}}/$${ACCOUNT}/g" \
		> $@

export TEST_SERVICE
service%.yaml:
	@echo "$${TEST_SERVICE}" | \
	    sed -e "s/{{NAME}}/service$*/g" \
		> $@

test: $(TEST_ARTIFACTS)
	-@for f in $^; do kubectl apply -f $$f; done

test-stop: $(TEST_ARTIFACTS)
	-@for f in $^; do kubectl delete -f $$f; done