# ProxyDHCP

## Guide

### Local Development

#### Prerequisites

```bash
# start tink server. add any hardware profiles needed
# vagrant up provisioner
(cd deployments/tink-server; docker-compose up -d)

# start nginx server to serve kernels and initrds
(cd ~/repos/tinkerbell/sandbox/deploy/state/webroot && docker run -d --name bootloaders -v ${PWD}:/usr/share/nginx/html/ -p 9090:80 nginx:alpine)

# start dhcp server
multipass shell dhcp
cd coredhcp/cmds/coredhcp
# leases.txt has needed dhcp host reservations, dhcp lease reservations are not supported
sudo ./coredhcp --conf config.yml
```

#### Local Direct

```bash
# start boots
sudo BOOTS_PUBLIC_FQDN=192.168.2.225 MIRROR_HOST=192.168.2.225:9090 PUBLIC_FQDN=192.168.2.225 DOCKER_REGISTRY=docker.io REGISTRY_USERNAME=none REGISTRY_PASSWORD=none TINKERBELL_GRPC_AUTHORITY=localhost:42113 TINKERBELL_CERT_URL=http://localhost:42114/cert DATA_MODEL_VERSION=1 FACILITY_CODE=onprem API_AUTH_TOKEN=empty API_CONSUMER_TOKEN=empty go run ./cmd/boots -http-addr 192.168.2.225:80 -tftp-addr 192.168.2.225:69 -proxyDHCP-addr 192.168.2.225:67 -proxyDHCP

# go and start a VM
```

#### Kubernetes

```bash
# start minikube
# reference this: https://dpb587.me/post/2020/04/11/minikube-and-bridged-networking/ bridged mode
minikube config set cpus 4
minikube config set disk-size 65536
minikube config set memory 4096
minikube config set vm-driver virtualbox
minikube start --feature-gates=RemoveSelfLink=false # https://github.com/metallb/metallb/issues/794
# once its up, turn it off so we can add the bridged network interface
minikube stop
# manually add the bridged interface or follow the reference above
# edit the DHCP leases.txt from above with any IP in your subnet, restart DHCP
minikube start
# enable and configure metallb
minikube addons enable metalb
minikube addons configure metallb

# update deployments/kubernetes.yaml
#
# set the BOOTS_PUBLIC_FQDN which should be the first IP in the metallb range
# BOOTS_PUBLIC_FQDN=192.168.2.50
#
# set hostAliases IP. this should be the IP that tink server is listening, which should be your laptop's IP. the IP that is in the same subnet as about. for example 192.168.2.225
# hostAliases:
# - ip: "192.168.2.225"
#
# set the MIRROR_HOST. this is from where the kernel and initramfs are downloaded (the nginx server from above)
# - name: MIRROR_HOST
#   value: "192.168.2.225:9090"
#

# run tilt to deploy boots
tilt up -v --stream

# start up a dhcp relay on your laptop. This will capture the broadcast traffic and send it unicast to k8s
# K8s doesn't forward broadcast traffic to pods - https://github.com/metallb/metallb/issues/344
git clone https://github.com/pyke369/pdhcp
cd pdhcp
make
# the make command will error out but the pdhcp binary should have be created successfully
# -i is the interface you want to listen on
# -r is the IP of boots
# -s is the IP on the interface defined by -i
./pdhcp -i en7 -r 192.168.2.50 -s 192.168.2.225
#
# take a deep breathe, you're ready to start iterating on boots
# start a VM
# be aware if you are using virtualbox that you cannot use the reset command on the VM. there's a bug and it wont PXE correctly
# you have to power it off, and then start it each time.
```
