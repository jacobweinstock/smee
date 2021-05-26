package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/libp2p/go-reuseport"
	"github.com/packethost/pkg/log"
	"go.universe.tf/netboot/dhcp4"
	"golang.org/x/sync/errgroup"
)

// https://github.com/danderson/netboot/blob/bdaec9d82638460bf166fb98bdc6d97331d7bd80/dhcp4/testdata/dhcp.parsed

// bootfile returns the Bootfile-Name that will be used for PXE boot responses [option 67]
// normally based on the arch (based off option 93), user-class (option 77) and hardware ID (mac) of a booting machine
type bootfile func(mach Machine) string

// bootserver returns the Server-Name option that will be used for PXE boot responses [option 66]
type bootserver func() string

// customBootfile defines how a Bootfile-Name is determined
func customBootfile(publicFDQN string) bootfile {
	return func(mach Machine) string {
		var filename string
		switch strings.ToLower(mach.UserClass) {
		case "ipxe", "tinkerbell":
			filename = fmt.Sprintf("http://%v/auto.ipxe", publicFDQN)
		default:
			switch strings.ToLower(mach.Arch.String()) {
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

func TestServe(t *testing.T) {
	tests := map[string]struct {
		input string
		want  error
	}{
		"context canceled": {input: "127.0.0.1:60656", want: context.Canceled},
	}
	fqdn := "127.0.0.1"
	bfile := customBootfile(fqdn)
	sfile := customBootserver(fqdn)
	logger, _ := log.Init("github.com/tinkerbell/boots")

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			conn, err := dhcp4.NewConn(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			ctx, cancel := context.WithCancel(context.Background())
			g, ctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				return Serve(ctx, logger, conn, bfile, sfile)
			})
			// send DHCP request
			sendPacket(conn)
			if errors.Is(tc.want, context.Canceled) {
				cancel()
			}
			got := g.Wait()
			if !errors.Is(got, tc.want) {
				cancel()
				t.Fatalf("expected error of type %T, got: %T", tc.want, got)
			}
			cancel()
		})
		//t.Fatal()
	}
}

func sendPacket(conn *dhcp4.Conn) {
	con, err := reuseport.Dial("udp4", "127.0.0.1:35689", "127.0.0.1:60656")
	if err != nil {
		fmt.Println("1", err)
		return
	}

	mac, err := net.ParseMAC("ce:e7:7b:ef:45:f7")
	if err != nil {
		fmt.Println("2", err)
		return
	}
	opts := make(dhcp4.Options)
	var opt93 dhcp4.Option = 93
	opts[opt93] = []byte{0x0, 0x0}
	var opt77 dhcp4.Option = 77
	opts[opt77] = []byte("iPXE")
	p := &dhcp4.Packet{
		Type:          dhcp4.MsgDiscover,
		TransactionID: []byte("1234"),
		Broadcast:     true,
		HardwareAddr:  mac,
		Options:       opts,
	}

	bs, err := p.Marshal()
	if err != nil {
		fmt.Println("3", err)
		return
	}

	recPkt := make(chan *dhcp4.Packet)
	go func() {

		con, err := dhcp4.NewConn("")
		if err != nil {
			fmt.Println("err", err)
			return
		}

		/*
			pc, err := reuseport.Dial("udp4", "192.168.2.225:35689", "")
			if err != nil {
				fmt.Println("45 err", err)
				return
			}
			defer pc.Close()
		*/
		for {
			//var buf []byte
			//_, err := pc.Read(buf)
			pkt, _, err := con.RecvDHCP()
			if err == nil {
				//pkt, err := dhcp4.Unmarshal(buf[:])
				//if err == nil {
				if pkt.Type == dhcp4.MsgOffer {
					recPkt <- pkt
					return
				}
				//}
			} else {
				fmt.Println("err", err)
			}
		}
	}()

	con.Write(bs)
	//s.Write(bs)
	select {
	case <-time.After(time.Second * 2):
		close(recPkt)
		return
	case pkt := <-recPkt:
		fmt.Printf("Reply: %+v\n", pkt)
	}

}

func opts(num int) dhcp4.Options {
	opts := dhcp4.Options{93: {0x0, 0x0}}

	switch num {
	case 1:
	case 2:
		opts[97] = []byte{0x0, 0x0, 0x2, 0x0, 0x3, 0x0, 0x4, 0x0, 0x5, 0x0, 0x6, 0x0, 0x7, 0x0, 0x8, 0x0, 0x9}
	case 4:
		opts[97] = []byte{0x2, 0x0, 0x2, 0x0, 0x3, 0x0, 0x4, 0x0, 0x5, 0x0, 0x6, 0x0, 0x7, 0x0, 0x8, 0x0, 0x9}
	case 5:
		opts[97] = []byte{0x2, 0x0, 0x2}
	default:
		opts = make(dhcp4.Options)
	}
	return opts
}

func TestIsPXEPacket(t *testing.T) {
	tests := map[string]struct {
		input *dhcp4.Packet
		want  error
	}{
		"success, len(opt 97) == 0":             {input: &dhcp4.Packet{Type: dhcp4.MsgDiscover, Options: opts(1)}, want: nil},
		"success, len(opt 97) == 17":            {input: &dhcp4.Packet{Type: dhcp4.MsgDiscover, Options: opts(2)}, want: nil},
		"fail, missing opt 93":                  {input: &dhcp4.Packet{Type: dhcp4.MsgDiscover, Options: opts(3)}, want: errors.New("not a PXE boot request (missing option 93)")},
		"not discovery packet":                  {input: &dhcp4.Packet{Type: dhcp4.MsgAck}, want: fmt.Errorf("packet is %s, not %s", dhcp4.MsgAck, dhcp4.MsgDiscover)},
		"fail, len(opt 97) == 17, index 0 != 0": {input: &dhcp4.Packet{Type: dhcp4.MsgDiscover, Options: opts(4)}, want: errors.New("malformed client GUID (option 97), leading byte must be zero")},
		"fail, opt 97 wrong len":                {input: &dhcp4.Packet{Type: dhcp4.MsgDiscover, Options: opts(5)}, want: errors.New("malformed client GUID (option 97), wrong size")},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := isPXEPacket(tc.input)
			if got != nil {
				if diff := cmp.Diff(got.Error(), tc.want.Error()); diff != "" {
					t.Fatal(diff)
				}
			} else {
				if diff := cmp.Diff(got, tc.want); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

func machineType(n int) Machine {
	var m Machine
	switch n {
	case 0:
		m.Arch = ArchIA32
		m.Firm = FirmwareX86PC
	case 6:
		m.Arch = ArchIA32
		m.Firm = FirmwareEFI32
	case 7:
		m.Arch = ArchX64
		m.Firm = FirmwareEFI64
	case 9:
		m.Arch = ArchX64
		m.Firm = FirmwareEFIBC
	case 10:
		m.Arch = ArchX64
		m.Firm = FirmwareTinkerbellIpxe
		m.UserClass = "tinkerbell"
	case -1:
		m.Firm = Firmware(-1)
	}
	return m
}

func opt93(n int) dhcp4.Options {
	opts := make(dhcp4.Options)

	switch n {
	case 0:
		opts[93] = []byte{0x0, 0x0}
	case 6:
		opts[93] = []byte{0x0, 0x6}
	case 7:
		opts[93] = []byte{0x0, 0x7}
	case 8:
		opts[93] = []byte{0x0, 0x8}
	case 9:
		opts[93] = []byte{0x0, 0x9}
	case 10:
		opts[93] = []byte{0x0, 0x9}
		opts[77] = []byte("tinkerbell")
	}
	return opts
}

func TestProcessMachine(t *testing.T) {
	tests := map[string]struct {
		input       *dhcp4.Packet
		wantError   error
		wantMachine Machine
	}{
		"success arch 0":               {input: &dhcp4.Packet{Type: dhcp4.MsgDiscover, Options: opt93(0)}, wantError: nil, wantMachine: machineType(0)},
		"success arch 6":               {input: &dhcp4.Packet{Type: dhcp4.MsgDiscover, Options: opt93(6)}, wantError: nil, wantMachine: machineType(6)},
		"success arch 7":               {input: &dhcp4.Packet{Type: dhcp4.MsgDiscover, Options: opt93(7)}, wantError: nil, wantMachine: machineType(7)},
		"success arch 9":               {input: &dhcp4.Packet{Type: dhcp4.MsgDiscover, Options: opt93(9)}, wantError: nil, wantMachine: machineType(9)},
		"success userClass tinkerbell": {input: &dhcp4.Packet{Type: dhcp4.MsgDiscover, Options: opt93(10)}, wantError: nil, wantMachine: machineType(10)},
		"fail, unknown arch 8":         {input: &dhcp4.Packet{Type: dhcp4.MsgDiscover, Options: opt93(8)}, wantError: fmt.Errorf("unsupported client firmware type '%d' (please file a bug!)", 8)},
		"fail, bad opt 93":             {input: &dhcp4.Packet{Type: dhcp4.MsgDiscover, Options: opt93(4)}, wantError: fmt.Errorf("malformed DHCP option 93 (required for PXE): option not present in Options")},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := processMachine(tc.input)
			if err != nil {
				if tc.wantError != nil {
					if diff := cmp.Diff(err.Error(), tc.wantError.Error()); diff != "" {
						t.Fatal(diff)
					}
				} else {
					t.Fatalf("expected nil error, got: %v", err)
				}

			} else {
				if diff := cmp.Diff(m, tc.wantMachine); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

func TestCreateOffer(t *testing.T) {
	tests := map[string]struct {
		inputPkt  *dhcp4.Packet
		inputMach Machine
		wantError error
		want      *dhcp4.Packet
	}{
		"success": {
			inputPkt: &dhcp4.Packet{
				Options: dhcp4.Options{
					97: {0x0, 0x0, 0x2, 0x0, 0x3, 0x0, 0x4, 0x0, 0x5, 0x0, 0x6, 0x0, 0x7, 0x0, 0x8, 0x0, 0x9},
				},
			},
			want: &dhcp4.Packet{
				Type:           dhcp4.MsgOffer,
				Broadcast:      true,
				ServerAddr:     net.IP{127, 0, 0, 1},
				BootServerName: "127.0.0.1",
				BootFilename:   "undionly.kpxe",
				Options: dhcp4.Options{
					43: {0x06, 0x01, 0x08, 0xff},
					54: {0x7f, 0x00, 0x00, 0x01},
					60: {0x50, 0x58, 0x45, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74},
					97: {0x0, 0x0, 0x2, 0x0, 0x3, 0x0, 0x4, 0x0, 0x5, 0x0, 0x6, 0x0, 0x7, 0x0, 0x8, 0x0, 0x9},
				},
			},
			inputMach: machineType(0),
		},
	}
	fqdn := "127.0.0.1"
	sfile := customBootserver(fqdn)
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			bfile := customBootfile(fqdn)
			pkt, err := createOffer(tc.inputPkt, tc.inputMach, net.IP{127, 0, 0, 1}, bfile, sfile)
			if err != nil {
				if tc.wantError != nil {
					if diff := cmp.Diff(err.Error(), tc.wantError.Error()); diff != "" {
						t.Fatal(diff)
					}
				} else {
					t.Fatalf("expected nil error, got: %v", err)
				}

			} else {
				if diff := cmp.Diff(pkt, tc.want); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

func TestArchString(t *testing.T) {
	tests := map[string]struct {
		input Architecture
		want  string
	}{
		"ArchIA32":    {input: ArchIA32, want: "IA32"},
		"ArchX64":     {input: ArchX64, want: "X64"},
		"Arch2a2":     {input: Arch2a2, want: "2a2"},
		"ArchAarch64": {input: ArchAarch64, want: "aarch64"},
		"ArchUefi":    {input: ArchUefi, want: "uefi"},
		"ArchHua":     {input: ArchHua, want: "hua"},
		"unknown":     {input: Architecture(6), want: "Unknown architecture"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			arch := tc.input.String()
			if diff := cmp.Diff(arch, tc.want); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
