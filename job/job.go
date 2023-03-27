package job

import (
	"bytes"
	"context"
	"net"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"github.com/tinkerbell/boots/conf"
	"github.com/tinkerbell/boots/dhcp"
	"github.com/tinkerbell/boots/hardware"
	"github.com/tinkerbell/tink/pkg/apis/core/v1alpha1"
)

// JobManager creates jobs.
type Manager interface {
	CreateFromRemoteAddr(ctx context.Context, ip string) (context.Context, *Job, error)
	CreateFromDHCP(context.Context, net.HardwareAddr, net.IP, string) (context.Context, *Job, error)
}

// Creator is a type that can create jobs.
type Creator struct {
	finder             hardware.Finder
	logger             logr.Logger
	ExtraKernelParams  []string
	Registry           string
	RegistryUsername   string
	RegistryPassword   string
	TinkServerTLS      bool
	TinkServerGRPCAddr string
	OSIEURLOverride    string
}

// NewCreator returns a manager that can create jobs.
func NewCreator(logger logr.Logger, finder hardware.Finder) *Creator {
	return &Creator{
		finder: finder,
		logger: logger,
	}
}

// Job holds per request data.
type Job struct {
	mac      net.HardwareAddr
	ip       net.IP
	start    time.Time
	dhcp     dhcp.Config
	hardware *v1alpha1.HardwareSpec
	instance *v1alpha1.MetadataInstance
	ifDHCP   *v1alpha1.Interface

	Logger             logr.Logger
	NextServer         net.IP
	IpxeBaseURL        string
	BootsBaseURL       string
	ExtraKernelParams  []string
	Registry           string
	RegistryUsername   string
	RegistryPassword   string
	TinkServerTLS      bool
	TinkServerGRPCAddr string
	OSIEURLOverride    string
}

// AllowPxe returns the value from the hardware data
// in tink server defined at network.interfaces[].netboot.allow_pxe.
func (j Job) AllowPXE() bool {
	if j.hardware != nil {
		for _, elem := range j.hardware.Interfaces {
			hwAddr, err := net.ParseMAC(elem.DHCP.MAC)
			if err != nil {
				continue
			}
			if bytes.Equal(hwAddr, j.mac) {
				return *elem.Netboot.AllowPXE
			}
		}
	}

	return false
}

// CreateFromDHCP looks up hardware using the MAC from cacher to create a job.
// OpenTelemetry: If a hardware record is available and has an in-band traceparent
// specified, the returned context will have that trace set as its parent and the
// spans will be linked.
func (c *Creator) CreateFromDHCP(ctx context.Context, mac net.HardwareAddr, giaddr net.IP, circuitID string) (context.Context, *Job, error) {
	j := &Job{
		mac:    mac,
		start:  time.Now(),
		Logger: c.logger,
	}
	d, err := c.finder.FindByMAC(ctx, mac)
	if err != nil {
		return ctx, nil, errors.WithMessage(err, "discover from dhcp message")
	}
	m := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, elem := range d.Spec.Interfaces {
		if elem.DHCP != nil && elem.DHCP.MAC == mac.String() {
			m, err = net.ParseMAC(elem.DHCP.MAC)
			if err != nil {
				m = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			}
			j.ip = net.ParseIP(elem.DHCP.IP.Address)
		}
	}
	if bytes.Equal(m, net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
		c.logger.Error(errors.New("somehow got a zero mac"), "somehow got a zero mac")

		return ctx, nil, errors.New("somehow got a zero mac")
	}
	j.mac = m

	newCtx, err := j.setup(ctx, &d.Spec)
	if err != nil {
		return ctx, nil, err
	}

	return newCtx, j, nil
}

// CreateFromRemoteAddr looks up hardware using the IP from cacher to create a job.
// OpenTelemetry: If a hardware record is available and has an in-band traceparent
// specified, the returned context will have that trace set as its parent and the
// spans will be linked.
func (c *Creator) CreateFromRemoteAddr(ctx context.Context, ip string) (context.Context, *Job, error) {
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		return ctx, nil, errors.Wrap(err, "splitting host:ip")
	}

	return c.createFromIP(ctx, net.ParseIP(host))
}

// createFromIP looks up hardware using the IP from cacher to create a job.
// OpenTelemetry: If a hardware record is available and has an in-band traceparent
// specified, the returned context will have that trace set as its parent and the
// spans will be linked.
func (c *Creator) createFromIP(ctx context.Context, ip net.IP) (context.Context, *Job, error) {
	j := &Job{
		ip:                 ip,
		start:              time.Now(),
		Logger:             c.logger,
		ExtraKernelParams:  c.ExtraKernelParams,
		Registry:           c.Registry,
		RegistryUsername:   c.RegistryUsername,
		RegistryPassword:   c.RegistryPassword,
		TinkServerTLS:      c.TinkServerTLS,
		TinkServerGRPCAddr: c.TinkServerGRPCAddr,
		OSIEURLOverride:    c.OSIEURLOverride,
	}

	c.logger.Info("discovering from ip", "ip", ip)
	d, err := c.finder.FindByIP(ctx, ip)
	if err != nil {
		return ctx, nil, errors.WithMessage(err, "discovering from ip address")
	}
	mac := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, elem := range d.Spec.Interfaces {
		if elem.DHCP != nil && elem.DHCP.IP != nil && elem.DHCP.IP.Address == ip.String() {
			mac, err = net.ParseMAC(elem.DHCP.MAC)
			if err != nil {
				mac = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			}
			j.ip = net.ParseIP(elem.DHCP.IP.Address)
		}
	}
	if bytes.Equal(mac, net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
		c.logger.Error(errors.New("somehow got a zero mac"), "somehow got a zero mac", "ip", ip)

		return ctx, nil, errors.New("somehow got a zero mac")
	}
	j.mac = mac

	ctx, err = j.setup(ctx, &d.Spec)
	if err != nil {
		return ctx, nil, err
	}

	return ctx, j, nil
}

// setup initializes the job from the discovered hardware record with the DHCP
// settings filled in from that record. If the inbound discovered hardware
// has an in-band traceparent populated, the context has its trace modified
// so that it points at the incoming traceparent from the hardware. A span
// link is applied in the process. The returned context's parent trace will
// be set to the traceparent value.
func (j *Job) setup(ctx context.Context, hw *v1alpha1.HardwareSpec) (context.Context, error) {
	j.hardware = hw
	j.instance = j.metadataInstance()
	j.Logger = j.Logger.WithValues("instance.id", j.instance.ID)

	j.ip = j.getIPByMac(j.mac)
	if j.ip == nil {
		return ctx, errors.New("could not find IP address")
	}

	for _, iface := range hw.Interfaces {
		if iface.DHCP != nil && iface.DHCP.IP != nil && (iface.DHCP.IP.Address == j.ip.String() || iface.DHCP.MAC == j.mac.String()) {
			j.ifDHCP = &iface
		}
	}

	ip := net.ParseIP(j.ifDHCP.DHCP.IP.Address)
	netmask := net.ParseIP(j.ifDHCP.DHCP.IP.Netmask)
	gateway := net.ParseIP(j.ifDHCP.DHCP.IP.Gateway)
	j.dhcp.Setup(j.Logger, ip, netmask, gateway)
	j.dhcp.SetLeaseTime(time.Duration(j.ifDHCP.DHCP.LeaseTime))
	j.dhcp.SetDHCPServer(conf.PublicIPv4) // used for the unicast DHCPREQUEST
	ns := []net.IP{}
	for _, n := range j.ifDHCP.DHCP.NameServers {
		s := net.ParseIP(n)
		ns = append(ns, s)
	}
	j.dhcp.SetDNSServers(ns)

	if hostname := j.ifDHCP.DHCP.Hostname; hostname != "" {
		j.dhcp.SetHostname(hostname)
	}

	// set option 43.116 to vlan id. If ifRecord.DHCP.VLANID is "", then j.dhcp.SetOpt43SubOpt is a no-op.
	j.dhcp.SetOpt43SubOpt(116, j.ifDHCP.DHCP.VLANID)

	return ctx, nil
}
