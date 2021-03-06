## Development

1. Install the prerequisites in the [iapingress-controller chart README.md](./charts/iapingress-controller/README.md)

```
make install-cert-manager install-kube-metacontroller
```

2. Install the NFS chart (for deps cache), the iapingress-controller chart with godev enabled, copy the source, install the go dependencies and build the controller from source. This will also run the controller in the dev container.

```
make install
```

3. Make a change to the golang source, then run `make build` to rebuild and re-run your change. Run `make build podlogs` to tail the container logs after building.

## Testing

1. Run `make test` to deploy example service and iapingress resource. Run `make podlogs` to see controller logs.
2. Run `make test-stop` to delete the test iapingress resource and test service.

## Building Container Image

1. Build image using container builder in current project:

```
make image
```