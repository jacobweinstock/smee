package job

import (
	"fmt"
	"net"
	"strings"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/tinkerbell/tink/pkg/apis/core/v1alpha1"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Mock Job

// NewMock returns a mock Job with only minimal fields set, it is useful only for tests.
func NewMock(slug string) Mock {
	slugs := strings.Split(slug, ":")
	slug = slugs[0]

	arch := "x86_64"
	if strings.Contains(slug, ".arm") || strings.Contains(slug, "baremetal_2a") || strings.Contains(slug, "baremetal_hua") {
		arch = "aarch64"
	}

	uefi := false
	if arch == "aarch64" || slug == "c2.medium.x86" {
		uefi = true
	}

	mockLog := defaultLogger("debug")

	return Mock{
		Logger:   mockLog.WithValues("mock", true, "slug", slug, "arch", arch, "uefi", uefi),
		hardware: &v1alpha1.HardwareSpec{},
		instance: &v1alpha1.MetadataInstance{},
	}
}

// defaultLogger is zap logr implementation.
func defaultLogger(level string) logr.Logger {
	config := zap.NewProductionConfig()
	config.OutputPaths = []string{"stdout"}
	switch level {
	case "debug":
		config.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	default:
		config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}
	zapLogger, err := config.Build()
	if err != nil {
		panic(fmt.Sprintf("who watches the watchmen (%v)?", err))
	}

	return zapr.NewLogger(zapLogger)
}

func (m Mock) Job() Job {
	return Job(m)
}

func (m *Mock) DropInstance() {
	m.instance = nil
}

func (m *Mock) SetIP(ip net.IP) {
	m.ip = ip
}

func (m *Mock) SetIPXEScriptURL(url string) {
	m.ifDHCP.Netboot.IPXE.URL = url
}

func (m *Mock) SetMAC(mac string) {
	_m, err := net.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	m.mac = _m
}

func (m *Mock) SetRescue(b bool) {
	i := m.instance
	i.Rescue = b
}
