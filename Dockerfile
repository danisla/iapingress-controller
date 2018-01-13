FROM alpine:3.7
RUN apk add --update ca-certificates bash curl && \
    curl -o /usr/local/bin/kubectl https://storage.googleapis.com/kubernetes-release/release/v1.8.5/bin/linux/amd64/kubectl && \
    chmod +x /usr/local/bin/kubectl
COPY gopath/bin/iapingress-controller /iapingress-controller
ENTRYPOINT ["/iapingress-controller"]