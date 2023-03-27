package hardware

import (
	"context"
	"net"

	"github.com/tinkerbell/tink/pkg/apis/core/v1alpha1"
)

// Finder interface for retrieving hardware spec.
type Finder interface {
	FindByIP(context.Context, net.IP) (v1alpha1.Hardware, error)
	FindByMAC(context.Context, net.HardwareAddr) (v1alpha1.Hardware, error)
}
