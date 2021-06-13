package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/inetaf/netaddr"
	"github.com/packethost/pkg/log"
	"go.universe.tf/netboot/dhcp4"
	"golang.org/x/net/ipv4"
)

func ServePXE(ctx context.Context, l log.Logger, conn net.PacketConn, bootfile func(f Firmware) string, bootserver func() string) error {
	buf := make([]byte, 1024)
	lr := ipv4.NewPacketConn(conn)
	if err := lr.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		return fmt.Errorf("couldn't get interface metadata on PXE port: %s", err)
	}

	for {
		n, msg, addr, err := lr.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("receiving packet: %s", err)
		}

		pkt, err := dhcp4.Unmarshal(buf[:n])
		if err != nil {
			l.Info("PXE", "Packet from %s is not a DHCP packet: %s", addr, err)
			continue
		}
		var eightyTwo dhcp4.Option = 82
		et, err := pkt.Options.Bytes(eightyTwo)
		fmt.Printf("opt 82 err: %v\n", err)
		fmt.Printf("opt 82: %v\n", string(et))

		if err = isPXEPacket(pkt); err != nil {
			l.Info("PXE Ignoring packet from %s (%s): %s", pkt.HardwareAddr, addr, err)
		}
		fwtype, err := validatePXE(pkt)
		if err != nil {
			l.Info("PXE Unusable packet from %s (%s): %s", pkt.HardwareAddr, addr, err)
			continue
		}
		i, _ := netaddr.ParseIP(bootserver())
		resp, err := offerPXE(pkt, i.IPAddr().IP, fwtype, bootfile, bootserver)
		if err != nil {
			l.Info("PXE Failed to construct PXE offer for %s (%s): %s", pkt.HardwareAddr, addr, err)
			continue
		}
		fmt.Printf("resp: %+v\n", resp)
		bs, err := resp.Marshal()
		if err != nil {
			l.Info("PXE Failed to marshal PXE offer for %s (%s): %s", pkt.HardwareAddr, addr, err)
			continue
		}

		if _, err := lr.WriteTo(bs, &ipv4.ControlMessage{IfIndex: msg.IfIndex}, addr); err != nil {
			l.Info("PXE Failed to send PXE response to %s (%s): %s", pkt.HardwareAddr, addr, err)
		}
		fmt.Println("sent pxe packet", addr)
	}
}

func validatePXE(pkt *dhcp4.Packet) (fwtype Firmware, err error) {
	fwt, err := pkt.Options.Uint16(93)
	if err != nil {
		return 0, fmt.Errorf("malformed DHCP option 93 (required for PXE): %s", err)
	}
	switch fwt {
	case 6:
		fwtype = FirmwareEFI32
	case 7:
		fwtype = FirmwareEFI64
	case 9:
		fwtype = FirmwareEFIBC
	default:
		return 0, fmt.Errorf("unsupported client firmware type '%d' (please file a bug!)", fwt)
	}
	/*
		if s.Ipxe[fwtype] == nil {
			return 0, fmt.Errorf("unsupported client firmware type '%d' (please file a bug!)", fwtype)
		}
	*/

	guid := pkt.Options[97]
	switch len(guid) {
	case 0:
		// Accept missing GUIDs even though it's a spec violation,
		// same as in dhcp.go.
	case 17:
		if guid[0] != 0 {
			return 0, errors.New("malformed client GUID (option 97), leading byte must be zero")
		}
	default:
		return 0, errors.New("malformed client GUID (option 97), wrong size")
	}

	return fwtype, nil
}

func offerPXE(pkt *dhcp4.Packet, serverIP net.IP, fwtype Firmware, bootfile func(f Firmware) string, bootserver func() string) (resp *dhcp4.Packet, err error) {
	resp = &dhcp4.Packet{
		Type:           dhcp4.MsgAck,
		TransactionID:  pkt.TransactionID,
		HardwareAddr:   pkt.HardwareAddr,
		ClientAddr:     pkt.ClientAddr,
		RelayAddr:      pkt.RelayAddr,
		ServerAddr:     serverIP,
		BootServerName: bootserver(),
		BootFilename:   bootfile(fwtype),
		Options: dhcp4.Options{
			dhcp4.OptServerIdentifier: serverIP,
			dhcp4.OptVendorIdentifier: []byte("PXEClient"),
		},
	}
	if pkt.Options[97] != nil {
		resp.Options[97] = pkt.Options[97]
	}
	fmt.Println("in pxe firm", fwtype)
	fmt.Println("in pxe bootserver()", bootserver())
	fmt.Println("in pxe bootfile(fwtype)", bootfile(fwtype))

	return resp, nil
}