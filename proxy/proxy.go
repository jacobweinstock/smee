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

// Firmware describes a kind of firmware attempting to boot.
//
// This should only be used for selecting the right bootloader within
// Pixiecore, kernel selection should key off the more generic
// Architecture.
type Firmware int

// Architecture describes a kind of CPU architecture.
type Architecture int

// A Machine describes a machine that is attempting to boot.
type Machine struct {
	MAC  net.HardwareAddr
	Arch Architecture
}

// The bootloaders that Pixiecore knows how to handle.
const (
	FirmwareX86PC         Firmware = iota // "Classic" x86 BIOS with PXE/UNDI support
	FirmwareEFI32                         // 32-bit x86 processor running EFI
	FirmwareEFI64                         // 64-bit x86 processor running EFI
	FirmwareEFIBC                         // 64-bit x86 processor running EFI
	FirmwareX86Ipxe                       // "Classic" x86 BIOS running iPXE (no UNDI support)
	FirmwarePixiecoreIpxe                 // Pixiecore's iPXE, which has replaced the underlying firmware
)

// Architecture types that Pixiecore knows how to boot.
//
// These architectures are self-reported by the booting machine. The
// machine may support additional execution modes. For example, legacy
// PC BIOS reports itself as an ArchIA32, but may also support ArchX64
// execution.
const (
	// ArchIA32 is a 32-bit x86 machine. It _may_ also support X64
	// execution, but Pixiecore has no way of knowing.
	ArchIA32 Architecture = iota
	// ArchX64 is a 64-bit x86 machine (aka amd64 aka X64).
	ArchX64
)

type Server struct {
	logger log.Logger
	// Ipxe lists the supported bootable Firmwares, and their
	// associated ipxe binary.
	Ipxe     map[Firmware][]byte
	HTTPPort string
}

func Serve(ctx context.Context, logger log.Logger, listenAddr string, bootfile func(arch, userClass, hardwareID string) string, bootserver func() string) error {
	for {
		select {
		case <-ctx.Done():
			logger.Info("exiting proxyDHCP")
			return nil
		default:

			/*
				s := &UDPServer{
					listenAddress: listenAddr,
					handlePacket: func(conn *net.UDPConn, raddr *net.UDPAddr, braddr *net.UDPAddr, rawIncomingUDPPacket []byte) (int, error) {
						return handleProxyDHCPPacket(conn, raddr, braddr, rawIncomingUDPPacket)
					},
				}
				//s := servers.NewProxyDHCPServer(listenAddr, "", "", eventsHandler, false)
				err := s.ListenAndServe(ctx)
				return err
			*/
			s := &Server{logger: logger, HTTPPort: "8080"}
			newDHCP, err := dhcp4.NewConn(listenAddr)
			if err != nil {
				return err
			}
			defer newDHCP.Close()
			err = s.serveProxyDHCP(ctx, newDHCP, bootfile, bootserver)
			return err

		}
	}
}

func (s *Server) serveProxyDHCP(ctx context.Context, conn *dhcp4.Conn, bootfile func(arch, userClass, hardwareID string) string, bootserver func() string) error {
	go func() {
		for {
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
				if err = s.isBootDHCP(pkt); err != nil {
					s.logger.Info(fmt.Sprintf("Ignoring packet from %s: %s", pkt.HardwareAddr, err))
					return
				}
				mach, fwtype, err := s.validateDHCP(pkt)
				if err != nil {
					s.logger.Info(fmt.Sprintf("Unusable packet from %s: %s", pkt.HardwareAddr, err))
					return
				}

				s.logger.Info(fmt.Sprintf("Got valid request to boot %s (%s)", mach.MAC, mach.Arch))
				/*
					if fwtype == FirmwarePixiecoreIpxe {
						//s.machineEvent(pkt.HardwareAddr, machineStateProxyDHCPIpxe, "Offering to boot iPXE")
						s.logger.Info(fmt.Sprintf("Offering to boot iPXE %s", pkt.HardwareAddr))
					} else {
						//s.machineEvent(pkt.HardwareAddr, machineStateProxyDHCP, "Offering to boot")
						s.logger.Info(fmt.Sprintf("Offering to boot %s", pkt.HardwareAddr))
					}
				*/

				// Machine should be booted.
				serverIP, err := interfaceIP(intf)
				if err != nil {
					s.logger.Info(fmt.Sprintf("Want to boot %s on %s, but couldn't get a source address: %s", pkt.HardwareAddr, intf.Name, err))
					return
				}

				resp, err := s.offerDHCP(pkt, mach, serverIP, fwtype)
				if err != nil {
					s.logger.Info(fmt.Sprintf("Failed to construct ProxyDHCP offer for %s: %s", pkt.HardwareAddr, err))
					return
				}
				userClass, _ := pkt.Options.String(77)
				resp.BootFilename = bootfile(mach.Arch.String(), userClass, mach.MAC.String())
				if fwtype == FirmwareX86Ipxe && !strings.HasPrefix(resp.BootFilename, "http") {
					resp.BootFilename = fmt.Sprintf("tftp://%s/%s", bootserver(), bootfile(mach.Arch.String(), userClass, mach.MAC.String()))
				}
				if !strings.HasPrefix(resp.BootFilename, "http") {
					resp.BootServerName = bootserver()
				}
				resp.BootServerName = bootserver()

				if err = conn.SendDHCP(resp, intf); err != nil {
					s.logger.Info(fmt.Sprintf("Failed to send ProxyDHCP offer for %s: %s", pkt.HardwareAddr, err))
					return
				}
			}()
		}
	}()

	<-ctx.Done()
	return ctx.Err()
}

func (s *Server) isBootDHCP(pkt *dhcp4.Packet) error {
	if pkt.Type != dhcp4.MsgDiscover {
		return fmt.Errorf("packet is %s, not %s", pkt.Type, dhcp4.MsgDiscover)
	}

	if pkt.Options[93] == nil {
		return errors.New("not a PXE boot request (missing option 93)")
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

func (s *Server) validateDHCP(pkt *dhcp4.Packet) (mach Machine, fwtype Firmware, err error) {
	fwt, err := pkt.Options.Uint16(93)
	if err != nil {
		return mach, 0, fmt.Errorf("malformed DHCP option 93 (required for PXE): %s", err)
	}

	// Basic architecture and firmware identification, based purely on
	// the PXE architecture option.
	switch fwt {
	case 0:
		mach.Arch = ArchIA32
		fwtype = FirmwareX86PC
	case 6:
		mach.Arch = ArchIA32
		fwtype = FirmwareEFI32
	case 7:
		mach.Arch = ArchX64
		fwtype = FirmwareEFI64
	case 9:
		mach.Arch = ArchX64
		fwtype = FirmwareEFIBC
	default:
		return mach, 0, fmt.Errorf("unsupported client firmware type '%d' (please file a bug!)", fwtype)
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
		if userClass == "iPXE" && fwtype == FirmwareX86PC {
			fwtype = FirmwareX86Ipxe
		}
		// If the client identifies as "pixiecore", we've already
		// chainloaded this client to the full-featured copy of iPXE
		// we supply. We have to distinguish this case so we don't
		// loop on the chainload step.
		if userClass == "pixiecore" {
			fwtype = FirmwarePixiecoreIpxe
		}
	}

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
			return mach, 0, errors.New("malformed client GUID (option 97), leading byte must be zero")
		}
	default:
		return mach, 0, errors.New("malformed client GUID (option 97), wrong size")
	}

	mach.MAC = pkt.HardwareAddr
	return mach, fwtype, nil
}

func (s *Server) offerPXE(pkt *dhcp4.Packet, serverIP net.IP, fwtype Firmware) (resp *dhcp4.Packet, err error) {
	resp = &dhcp4.Packet{
		//Type:           dhcp4.MsgAck,
		Type:           dhcp4.MsgOffer,
		TransactionID:  pkt.TransactionID,
		HardwareAddr:   pkt.HardwareAddr,
		ClientAddr:     pkt.ClientAddr,
		RelayAddr:      pkt.RelayAddr,
		ServerAddr:     serverIP,
		BootServerName: serverIP.String(),
		BootFilename:   fmt.Sprintf("%s/%d", pkt.HardwareAddr, fwtype),
		Options: dhcp4.Options{
			dhcp4.OptServerIdentifier: serverIP,
			dhcp4.OptVendorIdentifier: []byte("PXEClient"),
		},
	}
	if pkt.Options[97] != nil {
		resp.Options[97] = pkt.Options[97]
	}

	return resp, nil
}

func (s *Server) offerDHCP(pkt *dhcp4.Packet, mach Machine, serverIP net.IP, fwtype Firmware) (*dhcp4.Packet, error) {
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
	switch fwtype {
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
		resp.BootServerName = serverIP.String()
		resp.BootFilename = fmt.Sprintf("%s/%d", mach.MAC, fwtype)

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
		resp.BootFilename = fmt.Sprintf("tftp://%s/%s/%d", serverIP, mach.MAC, fwtype)

	case FirmwareEFI32, FirmwareEFI64, FirmwareEFIBC:
		// In theory, the response we send for FirmwareX86PC should
		// also work for EFI. However, some UEFI firmwares don't
		// support PXE properly, and will ignore ProxyDHCP responses
		// that try to bypass boot server discovery control.
		//
		// On the other hand, seemingly all firmwares support a
		// variant of the protocol where option 43 is not
		// provided. They behave as if option 43 had pointed them to a
		// PXE boot server on port 4011 of the machine sending the
		// ProxyDHCP response. Looking at TianoCore sources, I believe
		// this is the BINL protocol, which is Microsoft-specific and
		// lacks a specification. However, empirically, this code
		// seems to work.
		//
		// So, for EFI, we just provide a server name and filename,
		// and expect to be called again on port 4011 (which is in
		// pxe.go).
		resp.BootServerName = serverIP.String()
		resp.BootFilename = fmt.Sprintf("%s/%d", mach.MAC, fwtype)

	case FirmwarePixiecoreIpxe:
		// We've already gone through one round of chainloading, now
		// we can finally chainload to HTTP for the actual boot
		// script.
		resp.BootFilename = fmt.Sprintf("http://%s:%d/_/ipxe?arch=%d&mac=%s", serverIP, s.HTTPPort, mach.Arch, mach.MAC)

	default:
		return nil, fmt.Errorf("unknown firmware type %d", fwtype)
	}

	return resp, nil
}

func interfaceIP(intf *net.Interface) (net.IP, error) {
	addrs, err := intf.Addrs()
	if err != nil {
		return nil, err
	}

	// Try to find an IPv4 address to use, in the following order:
	// global unicast (includes rfc1918), link-local unicast,
	// loopback.
	fs := [](func(net.IP) bool){
		net.IP.IsGlobalUnicast,
		net.IP.IsLinkLocalUnicast,
		net.IP.IsLoopback,
	}
	for _, f := range fs {
		for _, a := range addrs {
			ipaddr, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipaddr.IP.To4()
			if ip == nil {
				continue
			}
			if f(ip) {
				return ip, nil
			}
		}
	}

	return nil, errors.New("no usable unicast address configured on interface")
}
