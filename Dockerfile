FROM alpine:3.7
RUN apk add --update ca-certificates bash
COPY gopath/bin/iapingress-controller /iapingress-controller
ENTRYPOINT ["/iapingress-controller"]