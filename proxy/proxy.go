package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/packethost/pkg/log"
	"go.universe.tf/netboot/dhcp4"
)

// The bootloaders that Boots knows how to handle.
const (
	FirmwareX86PC          Firmware = iota // "Classic" x86 BIOS with PXE/UNDI support
	FirmwareEFI32                          // 32-bit x86 processor running EFI
	FirmwareEFI64                          // 64-bit x86 processor running EFI
	FirmwareEFIBC                          // 64-bit x86 processor running EFI
	FirmwareX86Ipxe                        // "Classic" x86 BIOS running iPXE (no UNDI support)
	FirmwareTinkerbellIpxe                 // Tinkerbell's iPXE, which has replaced the underlying firmware
)

// Architecture types that Tinkerbell knows how to boot.
//
// These architectures are self-reported by the booting machine. The
// machine may support additional execution modes. For example, legacy
// PC BIOS reports itself as an ArchIA32, but may also support ArchX64
// execution.
const (
	// ArchIA32 is a 32-bit x86 machine. It _may_ also support X64
	// execution, but Tinkerbell has no way of knowing.
	ArchIA32 Architecture = iota
	// ArchX64 is a 64-bit x86 machine (aka amd64 aka X64).
	ArchX64
)

// Firmware describes a kind of firmware attempting to boot.
//
// This should only be used for selecting the right bootloader within
// Tinkerbell, kernel selection should key off the more generic
// Architecture.
type Firmware int

// Architecture describes a kind of CPU architecture.
type Architecture int

// A Machine describes a machine that is attempting to boot.
type Machine struct {
	MAC  net.HardwareAddr
	Arch Architecture
	Firm Firmware
}

// Serve proxyDHCP on network provided by the lAddr,
// f is the Bootfile-Name that will be used for PXE boot responses [option 67]
// normally based on the arch (based off option 93), user-class (option 77) and hardware ID (mac) of a booting machine
//
// s is the Server-Name option that will be used for PXE boot responses [option 66]
func Serve(ctx context.Context, l log.Logger, conn *dhcp4.Conn, bootfile func(arch, uClass string) string, bootserver func() string) error {
	go serveProxyDHCP(ctx, l, conn, bootfile, bootserver)
	<-ctx.Done()
	return ctx.Err()
}

// serveProxyDHCP
// 1. listen for generic DHCP packets [conn.RecvDHCP()]
// 2. check if the DHCP packet is requesting PXE boot [isBootDHCP(pkt)]
// 3.
func serveProxyDHCP(ctx context.Context, l log.Logger, conn *dhcp4.Conn, f func(arch, uClass string) string, s func() string) error {
	for {
		// RecvDHCP is a blocking call
		pkt, intf, err := conn.RecvDHCP()
		if err != nil {
			//s.logger.Info(fmt.Sprintf("Receiving DHCP packet: %s", err))
			continue
			//return fmt.Errorf("Receiving DHCP packet: %s", err)
		}
		if intf == nil {
			continue
			//return fmt.Errorf("Received DHCP packet with no interface information (this is a violation of dhcp4.Conn's contract, please file a bug)")
		}

		go func() {
			if err = isPXEPacket(pkt); err != nil {
				l.Info(fmt.Sprintf("Ignoring packet from %s: %s", pkt.HardwareAddr, err))
				return
			}
			mach, err := machineDetails(pkt)
			if err != nil {
				l.Info(fmt.Sprintf("Unusable packet from %s: %s", pkt.HardwareAddr, err))
				return
			}

			l.Info(fmt.Sprintf("Got valid request to boot %s (%s)", mach.MAC, mach.Arch))

			resp, err := dhcpOffer(pkt, mach, net.ParseIP(s()))
			if err != nil {
				l.Info(fmt.Sprintf("Failed to construct ProxyDHCP offer for %s: %s", pkt.HardwareAddr, err))
				return
			}
			userClass, _ := pkt.Options.String(77)
			resp.BootFilename = f(mach.Arch.String(), userClass)
			if mach.Firm == FirmwareX86Ipxe && !strings.HasPrefix(resp.BootFilename, "http") {
				resp.BootFilename = fmt.Sprintf("tftp://%s/%s", s(), f(mach.Arch.String(), userClass))
			}
			resp.BootServerName = s()

			if err = conn.SendDHCP(resp, intf); err != nil {
				l.Info(fmt.Sprintf("Failed to send ProxyDHCP offer for %s: %s", pkt.HardwareAddr, err))
				return
			}
		}()
	}
}

// isPXEPacket determines if the packet meets qualifications of a PXE request
// 1. is a DHCP discovery packet
// 2. option 93 is set
// 3. option 97 is correct length
func isPXEPacket(pkt *dhcp4.Packet) error {
	// should be a dhcp discover packet
	if pkt.Type != dhcp4.MsgDiscover {
		return fmt.Errorf("packet is %s, not %s", pkt.Type, dhcp4.MsgDiscover)
	}
	// option 93 must be set
	if pkt.Options[93] == nil {
		return errors.New("not a PXE boot request (missing option 93)")
	}
	// option 97 must be have correct length
	guid := pkt.Options[97]
	switch len(guid) {
	case 0:
		// A missing GUID is invalid according to the spec, however
		// there are PXE ROMs in the wild that omit the GUID and still
		// expect to boot. The only thing we do with the GUID is
		// mirror it back to the client if it's there, so we might as
		// well accept these buggy ROMs.
	case 17:
		if guid[0] != 0 {
			return errors.New("malformed client GUID (option 97), leading byte must be zero")
		}
	default:
		return errors.New("malformed client GUID (option 97), wrong size")
	}

	return nil
}

func (a Architecture) String() string {
	switch a {
	case ArchIA32:
		return "IA32"
	case ArchX64:
		return "X64"
	default:
		return "Unknown architecture"
	}
}

func machineDetails(pkt *dhcp4.Packet) (mach Machine, err error) {
	fwt, err := pkt.Options.Uint16(93)
	if err != nil {
		return mach, fmt.Errorf("malformed DHCP option 93 (required for PXE): %s", err)
	}
	// Basic architecture and firmware identification, based purely on
	// the PXE architecture option.
	switch fwt {
	case 0:
		mach.Arch = ArchIA32
		mach.Firm = FirmwareX86PC
	case 6:
		mach.Arch = ArchIA32
		mach.Firm = FirmwareEFI32
	case 7:
		mach.Arch = ArchX64
		mach.Firm = FirmwareEFI64
	case 9:
		mach.Arch = ArchX64
		mach.Firm = FirmwareEFIBC
	default:
		return mach, fmt.Errorf("unsupported client firmware type '%d' (please file a bug!)", fwt)
	}

	// Now, identify special sub-breeds of client firmware based on
	// the user-class option. Note these only change the "firmware
	// type", not the architecture we're reporting to Booters. We need
	// to identify these as part of making the internal chainloading
	// logic work properly.
	if userClass, err := pkt.Options.String(77); err == nil {
		// If the client has had iPXE burned into its ROM (or is a VM
		// that uses iPXE as the PXE "ROM"), special handling is
		// needed because in this mode the client is using iPXE native
		// drivers and chainloading to a UNDI stack won't work.
		if userClass == "iPXE" && mach.Firm == FirmwareX86PC {
			mach.Firm = FirmwareX86Ipxe
		}
		// If the client identifies as "tinkerbell", we've already
		// chainloaded this client to the full-featured copy of iPXE
		// we supply. We have to distinguish this case so we don't
		// loop on the chainload step.
		if userClass == "tinkerbell" {
			mach.Firm = FirmwareTinkerbellIpxe
		}
	}
	mach.MAC = pkt.HardwareAddr
	return mach, nil
}

// dhcpOffer returns the dhcp packet to offer to the client
func dhcpOffer(pkt *dhcp4.Packet, mach Machine, serverIP net.IP) (*dhcp4.Packet, error) {
	resp := &dhcp4.Packet{
		Type:          dhcp4.MsgOffer,
		TransactionID: pkt.TransactionID,
		Broadcast:     true,
		HardwareAddr:  mach.MAC,
		RelayAddr:     pkt.RelayAddr,
		ServerAddr:    serverIP,
		Options:       make(dhcp4.Options),
	}
	resp.Options[dhcp4.OptServerIdentifier] = serverIP
	// says the server should identify itself as a PXEClient vendor
	// type, even though it's a server. Strange.
	resp.Options[dhcp4.OptVendorIdentifier] = []byte("PXEClient")
	if pkt.Options[97] != nil {
		resp.Options[97] = pkt.Options[97]
	}
	switch mach.Firm {
	case FirmwareX86PC:
		// This is completely standard PXE: we tell the PXE client to
		// bypass all the boot discovery rubbish that PXE supports,
		// and just load a file from TFTP.
		pxe := dhcp4.Options{
			// PXE Boot Server Discovery Control - bypass, just boot from filename.
			6: []byte{8},
		}
		bs, err := pxe.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize PXE vendor options: %s", err)
		}
		resp.Options[43] = bs

	case FirmwareX86Ipxe:
		// Almost standard PXE, but the boot filename needs to be a URL.
		pxe := dhcp4.Options{
			// PXE Boot Server Discovery Control - bypass, just boot from filename.
			6: []byte{8},
		}
		bs, err := pxe.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize PXE vendor options: %s", err)
		}
		resp.Options[43] = bs
	default:
		return nil, fmt.Errorf("unknown firmware type %d", mach.Firm)
	}

	return resp, nil
}
