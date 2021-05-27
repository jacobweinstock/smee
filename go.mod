module github.com/tinkerbell/boots

go 1.16

require (
	bou.ke/monkey v1.0.2
	github.com/andreyvit/diff v0.0.0-20170406064948-c7f18ee00883
	github.com/avast/retry-go v2.2.0+incompatible
	github.com/davecgh/go-spew v1.1.1
	github.com/gammazero/workerpool v0.0.0-20200311205957-7b00833861c6
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e
	github.com/golang/mock v1.5.0
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.5
	github.com/google/uuid v1.2.0
	github.com/inetaf/netaddr v0.0.0-20210526175434-db50905a50be
	github.com/kevinburke/go-bindata v3.22.0+incompatible
	github.com/libp2p/go-reuseport v0.0.2
	github.com/packethost/cacher v0.0.0-20200825140532-0b62e6726807
	github.com/packethost/dhcp4-go v0.0.0-20190402165401-39c137f31ad3
	github.com/packethost/pkg v0.0.0-20210325161133-868299771ae0
	github.com/peterbourgon/ff/v3 v3.0.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.6.0
	github.com/sebest/xff v0.0.0-20160910043805-6c115e0ffa35
	github.com/stretchr/testify v1.6.1
	github.com/tinkerbell/tftp-go v0.0.0-20200825172122-d9200358b6cd
	github.com/tinkerbell/tink v0.0.0-20201109122352-0e8e57332303
	go.uber.org/zap v1.16.0
	go.universe.tf/netboot v0.0.0-20201124111825-bdaec9d82638
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b // indirect
	golang.org/x/net v0.0.0-20210420210106-798c2154c571
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/tools v0.1.0
	google.golang.org/genproto v0.0.0-20200921165018-b9da36f5f452 // indirect
	google.golang.org/grpc v1.37.0
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776 // indirect
	inet.af/netaddr v0.0.0-20200430175045-5aaf2097c7fc
)

replace (
	github.com/inetaf/netaddr v0.0.0-20210526175434-db50905a50be => inet.af/netaddr v0.0.0-20210526175434-db50905a50be
	github.com/sebest/xff v0.0.0-20160910043805-6c115e0ffa35 => github.com/packethost/xff v0.0.0-20190305172552-d3e9190c41b3
)
