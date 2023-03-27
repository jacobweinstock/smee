package job

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	dhcp4 "github.com/packethost/dhcp4-go"
	"github.com/tinkerbell/boots/conf"
	"github.com/tinkerbell/tink/pkg/apis/core/v1alpha1"
)

func TestSetPXEFilename(t *testing.T) {
	conf.PublicFQDN = "boots-testing.packet.net"

	setPXEFilenameTests := []struct {
		name       string
		hState     string
		id         string
		iState     string
		slug       string
		plan       string
		allowPXE   bool
		packet     bool
		arm        bool
		uefi       bool
		httpClient bool
		filename   string
	}{
		{
			name:   "just in_use",
			hState: "in_use",
		},
		{
			name:   "no instance state",
			hState: "in_use", id: "$instance_id", iState: "",
		},
		{
			name:   "instance not active",
			hState: "in_use", id: "$instance_id", iState: "not_active",
		},
		{
			name:   "instance active",
			hState: "in_use", id: "$instance_id", iState: "active",
		},
		{
			name:   "active not custom ipxe",
			hState: "in_use", id: "$instance_id", iState: "active", slug: "not_custom_ipxe",
		},
		{
			name:   "active custom ipxe",
			hState: "in_use", id: "$instance_id", iState: "active", slug: "custom_ipxe",
			filename: "undionly.kpxe",
		},
		{
			name:   "active custom ipxe with allow pxe",
			hState: "in_use", id: "$instance_id", iState: "active", allowPXE: true, slug: "custom_ipxe",
			filename: "undionly.kpxe",
		},
		{
			name: "arm",
			arm:  true, filename: "snp.efi",
		},
		{
			name: "x86 uefi",
			uefi: true, filename: "ipxe.efi",
		},
		{
			name: "x86 uefi http client",
			uefi: true, allowPXE: true, httpClient: true,
			filename: "http://" + conf.PublicFQDN + "/ipxe/ipxe.efi",
		},
		{
			name:     "all defaults",
			filename: "undionly.kpxe",
		},
		{
			name:   "packet iPXE",
			packet: true, filename: "nonexistent",
		},
		{
			name:   "packet iPXE PXE allowed",
			packet: true, id: "$instance_id", allowPXE: true, filename: "http://" + conf.PublicFQDN + "/auto.ipxe",
		},
	}

	for _, tt := range setPXEFilenameTests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("%+v", tt)

			if tt.plan == "" {
				tt.plan = "0"
			}

			j := Job{
				Logger: defaultLogger("debug"),
				mac:    net.HardwareAddr{0, 0, 0, 0, 0, 0},
				hardware: &v1alpha1.HardwareSpec{
					Metadata: &v1alpha1.HardwareMetadata{
						State: tt.hState,
						Facility: &v1alpha1.MetadataFacility{
							PlanSlug: tt.plan,
						},
						Instance: &v1alpha1.MetadataInstance{
							ID:    tt.id,
							State: tt.iState,
							OperatingSystem: &v1alpha1.MetadataInstanceOperatingSystem{
								Slug:   tt.slug,
								OsSlug: tt.slug,
							},
						},
					},
					Interfaces: []v1alpha1.Interface{
						{
							Netboot: &v1alpha1.Netboot{
								AllowPXE: &tt.allowPXE,
							},
							DHCP: &v1alpha1.DHCP{
								MAC:  "00:00:00:00:00:00",
								UEFI: tt.uefi,
							},
						},
					},
				},
				NextServer:   conf.PublicIPv4,
				IpxeBaseURL:  conf.PublicFQDN + "/ipxe",
				BootsBaseURL: conf.PublicFQDN,
			}
			rep := dhcp4.NewPacket(42)
			j.setPXEFilename(&rep, tt.packet, tt.arm, tt.uefi, tt.httpClient)
			filename := string(bytes.TrimRight(rep.File(), "\x00"))

			if tt.filename != filename {
				t.Fatalf("unexpected filename want:%q, got:%q", tt.filename, filename)
			}
		})
	}
}

func TestAllowPXE(t *testing.T) {
	for _, tt := range []struct {
		want bool
		id   string
	}{
		{want: true},
		{want: false},
	} {
		name := fmt.Sprintf("want=%t", tt.want)
		t.Run(name, func(t *testing.T) {
			j := Job{
				mac: net.HardwareAddr{0, 0, 0, 0, 0, 0},
				hardware: &v1alpha1.HardwareSpec{
					Interfaces: []v1alpha1.Interface{
						{
							Netboot: &v1alpha1.Netboot{
								AllowPXE: &tt.want,
							},
							DHCP: &v1alpha1.DHCP{
								MAC: "00:00:00:00:00:00",
							},
						},
					},
				},
			}
			got := j.AllowPXE()
			if got != tt.want {
				t.Fatalf("unexpected return, want: %t, got %t", tt.want, got)
			}
		})
	}
}
