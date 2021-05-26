package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/packethost/pkg/log"
	"github.com/tinkerbell/boots/proxy"
	"go.universe.tf/netboot/dhcp4"
)

// serveProxy is a place holder for proxyDHCP being a proper subcommand
// its goal is to serves proxyDHCP requests
func serveProxy(ctx context.Context, logger log.Logger, proxyAddr string, b getBootfile, s getServer) error {
	conn, err := dhcp4.NewConn(formatAddr(proxyAddr))
	if err != nil {
		return err
	}
	defer conn.Close()

	return proxy.Serve(ctx, logger, conn, b, s)
}

// getBootfile returns the Bootfile-Name that will be used for PXE boot responses [option 67]
// normally based on the arch (based off option 93),
// user-class (option 77), and firmware (based off option 93) of a booting machine
type getBootfile func(mach proxy.Machine) string

// getServer returns the Server-Name option that will be used for PXE boot responses [option 66]
type getServer func() string

// withBootfile defines how a Bootfile-Name is determined
func withBootfile(addr string) getBootfile {
	return func(m proxy.Machine) string {
		var filename string
		fmt.Printf("machine: %+v\n", m)
		// based on the machine arch set the filename
		switch m.Arch {
		case proxy.ArchHua, proxy.Arch2a2:
			filename = "snp-hua.efi"
		case proxy.ArchAarch64:
			filename = "snp-nolacp.efi"
		case proxy.ArchUefi:
			filename = "ipxe.efi"
		default:
			filename = "undionly.kpxe"
		}
		switch m.Firm {
		// if we're in iPXE we can use HTTP endpoint
		case proxy.FirmwareX86Ipxe, proxy.FirmwareTinkerbellIpxe:
			filename = fmt.Sprintf("http://%v/auto.ipxe", addr)
		case proxy.FirmwareX86PC, proxy.FirmwareEFI32, proxy.FirmwareEFI64, proxy.FirmwareEFIBC:
		default:
			filename = "/nonexistent"
		}
		return filename
	}
}

func withServer(addr string) getServer {
	return func() string {
		return addr
	}
}

// formatAddr will add 0.0.0.0 to a host:port combo that is without a host i.e. ":67"
func formatAddr(s string) string {
	if strings.HasPrefix(s, ":") {
		return "0.0.0.0" + s
	}
	return s
}
