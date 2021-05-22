package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/packethost/pkg/log"
	"github.com/tinkerbell/boots/proxy"
	"go.universe.tf/netboot/dhcp4"
)

// runProxyDHCP is a place holder for proxyDHCP being a proper subcommand
// its goal is to serves proxyDHCP requests
func runProxyDHCP(ctx context.Context, logger log.Logger, proxyAddr string, b bootfile, s bootserver) error {
	conn, err := dhcp4.NewConn(formatHostPort(proxyAddr))
	if err != nil {
		return err
	}
	defer conn.Close()

	return proxy.Serve(ctx, logger, conn, b, s)
}

// bootfile returns the Bootfile-Name that will be used for PXE boot responses [option 67]
// normally based on the arch (based off option 93), user-class (option 77) and hardware ID (mac) of a booting machine
type bootfile func(arch, uClass string) string

// bootserver returns the Server-Name option that will be used for PXE boot responses [option 66]
type bootserver func() string

// customBootfile defines how a Bootfile-Name is determined
func customBootfile(publicFDQN string) bootfile {
	return func(arch, uClass string) string {
		var filename string
		switch strings.ToLower(uClass) {
		case "ipxe", "tinkerbell":
			filename = fmt.Sprintf("http://%v/auto.ipxe", publicFDQN)
		default:
			switch strings.ToLower(arch) {
			case "hua", "2a2":
				filename = "snp-hua.efi"
			case "aarch64":
				filename = "snp-nolacp.efi"
			case "uefi":
				filename = "ipxe.efi"
			default:
				filename = "undionly.kpxe"
			}
		}
		return filename
	}
}

func customBootserver(publicFDQN string) bootserver {
	return func() string {
		return publicFDQN
	}
}

// formatHostPort will add 0.0.0.0 to a host:port combo that is without a host
// i.e. ":67"
func formatHostPort(s string) string {
	if strings.HasPrefix(s, ":") {
		return "0.0.0.0" + s
	}
	return s
}
