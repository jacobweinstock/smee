package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/packethost/pkg/log"
	"go.universe.tf/netboot/dhcp4"
	"golang.org/x/sync/errgroup"
)

// https://github.com/danderson/netboot/blob/bdaec9d82638460bf166fb98bdc6d97331d7bd80/dhcp4/testdata/dhcp.parsed

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

func TestServe(t *testing.T) {
	tests := map[string]struct {
		input string
		want  error
	}{
		"context canceled": {input: "127.0.0.1:35689", want: context.Canceled},
		//"network address error": {input: "127.0.0.1", want: &net.AddrError{}},
	}
	fqdn := "127.0.0.1"
	bfile := customBootfile(fqdn)
	sfile := customBootserver(fqdn)
	logger, _ := log.Init("github.com/tinkerbell/boots")
	conn, err := dhcp4.NewConn("127.0.0.1:35689")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			g, ctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				return Serve(ctx, logger, conn, bfile, sfile)
			})
			// send DHCP request
			sendPacket()
			time.Sleep(3 * time.Second)
			if errors.Is(tc.want, context.Canceled) {
				cancel()
			}
			got := g.Wait()
			if reflect.TypeOf(got) != reflect.TypeOf(tc.want) {
				cancel()
				t.Fatalf("expected error of type %T, got: %T", tc.want, got)
			}
			cancel()
		})
		//t.Fatal()
	}
}

func sendPacket() {
	s, err := net.Dial("udp4", "127.0.0.1:35689")
	if err != nil {
		return
	}

	mac, err := net.ParseMAC("ce:e7:7b:ef:45:f7")
	if err != nil {
		return
	}
	opts := make(dhcp4.Options)
	var opt93 dhcp4.Option = 93
	opts[opt93] = []byte{0x0, 0x0}
	p := &dhcp4.Packet{
		Type:          dhcp4.MsgDiscover,
		TransactionID: []byte("1234"),
		Broadcast:     true,
		HardwareAddr:  mac,
		Options:       opts,
	}
	bs, err := p.Marshal()
	if err != nil {
		//t.Fatalf("marshaling packet: %s", err)
		return
	}

	s.Write(bs)

}
