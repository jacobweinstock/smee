package job

import (
	"net"

	"github.com/tinkerbell/tink/pkg/apis/core/v1alpha1"
)

func getArch(h *v1alpha1.HardwareSpec, mac string) string {
	for _, elem := range h.Interfaces {
		if elem.DHCP.MAC == mac {
			return elem.DHCP.Arch
		}
	}

	return ""
}

func isUEFI(h *v1alpha1.HardwareSpec, mac string) bool {
	for _, elem := range h.Interfaces {
		if elem.DHCP.MAC == mac {
			return elem.DHCP.UEFI
		}
	}

	return false
}

func (j *Job) getOperatingSystem() *v1alpha1.MetadataInstanceOperatingSystem {
	if j.hardware != nil && j.hardware.Metadata != nil && j.hardware.Metadata.Instance != nil {
		return j.hardware.Metadata.Instance.OperatingSystem
	}

	return &v1alpha1.MetadataInstanceOperatingSystem{}
}

func (j *Job) metadataState() string {
	if j.hardware != nil && j.hardware.Metadata != nil {
		return j.hardware.Metadata.State
	}

	return ""
}

func (j *Job) metadataInstance() *v1alpha1.MetadataInstance {
	if j.hardware != nil && j.hardware.Metadata != nil {
		return j.hardware.Metadata.Instance
	}

	return &v1alpha1.MetadataInstance{}
}

func (j *Job) getIPByMac(mac net.HardwareAddr) net.IP {
	if j.hardware != nil {
		for _, elem := range j.hardware.Interfaces {
			if elem.DHCP.MAC == mac.String() {
				return net.ParseIP(elem.DHCP.IP.Address)
			}
		}
	}

	return nil
}

/*

func (j Job) IsARM() bool {
	return j.Arch() == "aarch64"
}

func (j Job) IsUEFI() bool {
	if h := j.hardware; h != nil {
		return h.HardwareUEFI(j.mac)
	}

	return false
}

func (j Job) Arch() string {
	if h := j.hardware; h != nil {
		return h.HardwareArch(j.mac)
	}

	return ""
}

func (j Job) BootDriveHint() string {
	if i := j.instance; i != nil {
		return i.BootDriveHint
	}

	return ""
}

func (j Job) InstanceID() string {
	if i := j.instance; i != nil {
		return i.ID
	}

	return ""
}

func (j Job) Rescue() bool {
	if i := j.instance; i != nil {
		return i.Rescue
	}

	return false
}

// UserData returns instance.UserData.
func (j Job) UserData() string {
	if i := j.instance; i != nil {
		return i.UserData
	}

	return ""
}

// IPXEScriptURL returns the value of instance.IPXEScriptURL.
func (j Job) IPXEScriptURL() string {
	if i := j.instance; i != nil {
		return i.IPXEScriptURL
	}

	return ""
}

// PasswordHash will return the password hash from the job instance if it exists
// PasswordHash first tries returning CryptedRootPassword if it exists and falls back to returning PasswordHash.
func (j Job) PasswordHash() string {
	if j.instance == nil {
		return ""
	}
	// TODO: remove this EMism
	if j.instance.CryptedRootPassword != "" {
		return j.instance.CryptedRootPassword
	}

	return j.instance.PasswordHash
}

// CustomData returns instance.CustomData.
func (j Job) CustomData() interface{} {
	if i := j.instance; i != nil && i.CustomData != nil {
		return i.CustomData
	}

	return nil
}

func (j Job) OperatingSystem() *v1alpha1.MetadataInstanceOperatingSystem {
	if i := j.instance; i != nil {
		return j.hardware.OperatingSystem()
	}

	return nil
}

func (j Job) ID() string {
	return j.mac.String()
}

func (j Job) FacilityCode() string {
	if h := j.hardware; h != nil {
		return h.HardwareFacilityCode()
	}

	return ""
}

func (j Job) PlanSlug() string {
	if h := j.hardware; h != nil {
		return h.HardwarePlanSlug()
	}

	return ""
}

func (j Job) PlanVersionSlug() string {
	if h := j.hardware; h != nil {
		return h.HardwarePlanVersionSlug()
	}

	return ""
}

func (j Job) Manufacturer() string {
	if h := j.hardware; h != nil {
		return h.HardwareManufacturer()
	}

	return ""
}

// PrimaryNIC returns the mac address of the NIC we expect to be dhcp/pxe'ing.
func (j Job) PrimaryNIC() net.HardwareAddr {
	return j.mac
}

// HardwareState will return (enrolled burn_in preinstallable preinstalling failed_preinstall provisionable provisioning deprovisioning in_use).
func (j Job) HardwareState() string {
	if h := j.hardware; h != nil && h.HardwareID() != "" {
		return string(h.HardwareState())
	}

	return ""
}

// OSIEVersion returns any non-standard osie versions specified in either the instance proper or in userdata or attached to underlying hardware.
func (j Job) OSIEVersion() string {
	if i := j.instance; i != nil {
		ov := i.GetServicesVersion().OSIE
		if ov != "" {
			return ov
		}
	}
	h := j.hardware
	if h == nil {
		return ""
	}

	return h.HardwareOSIEVersion()
}

// CanWorkflow checks if workflow is allowed.
func (j Job) CanWorkflow() bool {
	return j.hardware.HardwareAllowWorkflow(j.mac)
}

func (j Job) OSIEBaseURL() string {
	if h := j.hardware; h != nil {
		return j.hardware.OSIEBaseURL(j.mac)
	}

	return ""
}

func (j Job) KernelPath() string {
	if h := j.hardware; h != nil {
		return j.hardware.KernelPath(j.mac)
	}

	return ""
}

func (j Job) InitrdPath() string {
	if h := j.hardware; h != nil {
		return j.hardware.InitrdPath(j.mac)
	}

	return ""
}
*/
