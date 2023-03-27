package standalone

import (
	"context"
	"encoding/json"
	"net"
	"os"

	"github.com/pkg/errors"
	"github.com/tinkerbell/tink/pkg/apis/core/v1alpha1"
)

// HardwareFinder is a type for statically looking up hardware.
type Finder struct {
	data []*v1alpha1.Hardware
}

// HardwareStandalone implements the Hardware interface for standalone operation.
type HardwareStandalone struct {
	ID string `json:"id"`
	//Network     client.Network  `json:"network"`
	//Metadata    client.Metadata `json:"metadata"`
	Traceparent string `json:"traceparent"`
}

// NewHardwareFinder returns a Finder given a JSON file that is formatted as a slice of
// DiscoverStandalone.
func NewHardwareFinder(path string) (*Finder, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read file %q", path)
	}
	d := []*v1alpha1.Hardware{}
	// TODO: will need to translate from standalone to v1alpha1.Hardware
	err = json.Unmarshal(content, &d)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse configuration file %q", path)
	}
	f := &Finder{data: d}

	return f, nil
}

// ByIP returns a Discoverer for a particular IP.
func (f *Finder) FindByIP(_ context.Context, ip net.IP) (v1alpha1.Hardware, error) {
	for _, d := range f.data {
		for _, elem := range d.Spec.Interfaces {
			dataIP := net.ParseIP(elem.DHCP.IP.Address)
			if ip.Equal(dataIP) {
				return *d, nil
			}
		}
	}

	return v1alpha1.Hardware{}, errors.Errorf("no hardware found for ip: %v", ip)
}

// ByMAC returns a Discoverer for a particular MAC address.
func (f *Finder) FindByMAC(_ context.Context, mac net.HardwareAddr) (v1alpha1.Hardware, error) {
	for _, d := range f.data {
		for _, elem := range d.Spec.Interfaces {
			if elem.DHCP.MAC == mac.String() {
				return *d, nil
			}
		}
	}

	return v1alpha1.Hardware{}, errors.Errorf("no entry for MAC %q in standalone data", mac.String())
}
