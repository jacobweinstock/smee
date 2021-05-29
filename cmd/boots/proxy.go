package main

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/packethost/pkg/log"
	"github.com/tinkerbell/boots/proxy"
	"go.universe.tf/netboot/dhcp4"
)

// serveProxy is a place holder for proxyDHCP being a proper subcommand
// its goal is to serves proxyDHCP requests
func serveProxy(ctx context.Context, logger log.Logger, addr string, b getBootfile, s getServer) error {
	conn, err := dhcp4.NewConn(formatAddr(addr))
	if err != nil {
		return err
	}
	defer conn.Close()

	return proxy.Serve(ctx, logger, conn, b, s)
}

func serverPXE(ctx context.Context, logger log.Logger, addr string, b getBootfile, s getServer) error {
	pxe, err := net.ListenPacket("udp4", formatAddr(addr))
	if err != nil {
		return err
	}
	errCh := make(chan error)
	go func() {
		errCh <- proxy.ServePXE(ctx, logger, pxe, b, s)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case e := <-errCh:
		return e
	}
}

// getBootfile returns the Bootfile-Name that will be used for PXE boot responses [option 67]
// normally based on the arch (based off option 93),
// user-class (option 77), and firmware (based off option 93) of a booting machine
type getBootfile func(mach proxy.Firmware) string

// getServer returns the Server-Name option that will be used for PXE boot responses [option 66]
type getServer func() string

// withBootfile defines how a Bootfile-Name is determined
// TODO: handle 32bit vs 64bit
func withBootfile(addr string) getBootfile {
	return func(f proxy.Firmware) string {
		var filename string
		// based on the machine arch set the filename
		/*
			switch m.Arch {
			//case proxy.ArchHua, proxy.Arch2a2:
			//	filename = "snp-hua.efi"
			//case proxy.ArchAarch64:
			//	filename = "snp-nolacp.efi"
			case proxy.ArchIA32:
				filname = ""
			case proxy.ArchX64:
				filename = "ipxe.efi"
			default:
				filename = "undionly.kpxe"
			}
		*/

		lookup := map[proxy.Firmware]string{
			proxy.FirmwareX86Ipxe:        fmt.Sprintf("http://%v/auto.ipxe", addr),
			proxy.FirmwareTinkerbellIpxe: fmt.Sprintf("http://%v/auto.ipxe", addr),
			proxy.FirmwareX86IpxeEFI:     fmt.Sprintf("http://%v/auto.ipxe", addr),
			proxy.FirmwareX86PC:          "undionly.kpxe",
			proxy.FirmwareEFI32:          "ipxe.efi",
			proxy.FirmwareEFI64:          "ipxe.efi",
			proxy.FirmwareEFIBC:          "ipxe.efi",
		}
		filename, found := lookup[f]
		if !found {
			filename = "/nonexistent"

		}
		fmt.Printf("in proxy withBootfile firmware: %v\n", f)
		fmt.Printf("in proxy withBootfile filename: %v\n", filename)
		/*
			switch m.Firm {
			// if we're in iPXE we can use HTTP endpoint
			case proxy.FirmwareX86Ipxe, proxy.FirmwareTinkerbellIpxe:
				filename = fmt.Sprintf("http://%v/auto.ipxe", addr)
			case proxy.FirmwareX86PC:
				filename = "undionly.kpxe"
			case proxy.FirmwareEFI32, proxy.FirmwareEFI64, proxy.FirmwareEFIBC:
				filename = "ipxe.efi"
			default:
				filename = "/nonexistent"
			}
		*/
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
