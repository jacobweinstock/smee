package client

import (
	"bytes"
	"net"
	"net/http"

	"github.com/pkg/errors"
)

var (
	MinMAC = MACAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	MaxMAC = MACAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

type Getter interface {
	Get() (*http.Request, error)
}

// MACAddr is an IEEE 802 MAC-48 hardware address.
type MACAddr [6]byte

func (m MACAddr) HardwareAddr() net.HardwareAddr {
	return net.HardwareAddr(m[:])
}

func (m MACAddr) String() string {
	return net.HardwareAddr(m[:]).String()
}

func (m MACAddr) MarshalJSON() ([]byte, error) {
	return []byte(`"` + m.String() + `"`), nil
}

func (m *MACAddr) UnmarshalText(text []byte) error {
	const example = "00:00:00:00:00:00"
	if len(text) != len(example) {
		return errors.Errorf("expected a 48-bit hardware address, got %q", text)
	}
	*m = MinMAC

	mac, err := net.ParseMAC(string(text))
	if err != nil {
		return errors.Wrap(err, "parsing mac address")
	}
	copy(m[:], mac)

	return nil
}

func (m MACAddr) IsMin() bool {
	return bytes.Equal(m[:], MinMAC[:])
}

func (m MACAddr) IsMax() bool {
	return bytes.Equal(m[:], MaxMAC[:])
}
