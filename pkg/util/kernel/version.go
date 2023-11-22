//go:build linux

package kernel

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// Version is a numerical representation of a kernel version
type Version uint32

var hostVersion Version

// String returns a string representing the version in x.x.x format
func (v Version) String() string {
	a, b, c := v>>16, v>>8&0xff, v&0xff
	return fmt.Sprintf("%d.%d.%d", a, b, c)
}

// HostVersion returns the running kernel version of the host
func HostVersion() (Version, error) {
	if hostVersion != 0 {
		return hostVersion, nil
	}

	kv, err := CurrentKernelVersion()
	if err != nil {
		return 0, err
	}

	hostVersion = Version(kv)
	return hostVersion, nil
}

// ParseVersion parses a string in the format of x.x.x to a Version
func ParseVersion(s string) Version {
	var a, b, c byte
	_, _ = fmt.Sscanf(s, "%d.%d.%d", &a, &b, &c)
	return VersionCode(a, b, c)
}

// VersionCode returns a Version computed from the individual parts of a x.x.x version
func VersionCode(major, minor, patch byte) Version {
	// KERNEL_VERSION(a,b,c) = (a << 16) + (b << 8) + (c)
	// Per https://github.com/torvalds/linux/blob/db7c953555388571a96ed8783ff6c5745ba18ab9/Makefile#L1250
	return Version((uint32(major) << 16) + (uint32(minor) << 8) + uint32(patch))
}

// returns the current kernel version in LINUX_VERSION_CODE format (see KernelVersionFromReleaseString())
func CurrentKernelVersion() (uint32, error) {
	// We need extra checks for Debian and Ubuntu as they modify
	// the kernel version patch number for compatibility with
	// out-of-tree modules. Linux perf tools do the same for Ubuntu
	// systems: https://github.com/torvalds/linux/commit/d18acd15c
	//
	// See also:
	// https://kernel-handbook.alioth.debian.org/ch-versions.html
	// https://wiki.ubuntu.com/Kernel/FAQ
	version, err := currentVersionUbuntu()
	if err == nil {
		return version, nil
	}

	version, err = currentVersionDebian()
	if err == nil {
		return version, nil
	}

	return currentVersionUname()
}

func currentVersionUbuntu() (uint32, error) {
	// 文本内容 Ubuntu 6.2.0-33.33~22.04.1-generic 6.2.16
	procVersion, err := ioutil.ReadFile("/proc/version_signature")
	if err != nil {
		return 0, err
	}

	return parseUbuntuVersion(string(procVersion))
}

// Ubuntu 6.2.0-33.33~22.04.1-generic 6.2.16
func parseUbuntuVersion(procVersion string) (uint32, error) {
	var u1, u2, releaseString string
	_, err := fmt.Sscanf(procVersion, "%s %s %s", &u1, &u2, &releaseString)
	if err != nil {
		return 0, err
	}

	return kernelVersionFromReleaseString(releaseString)
}

func currentVersionDebian() (uint32, error) {
	procVersion, err := ioutil.ReadFile("/proc/version")
	if err != nil {
		return 0, fmt.Errorf("error reading /proc/version: %s", err)
	}

	return parseDebianVersion(string(procVersion))
}

var debianVersionRegex = regexp.MustCompile(`.* SMP Debian (\d+\.\d+.\d+-\d+)(?:\+[[:alnum:]]*)?.*`)

func parseDebianVersion(str string) (uint32, error) {
	match := debianVersionRegex.FindStringSubmatch(str)
	if len(match) != 2 {
		return 0, fmt.Errorf("failed to parse kernel version from /proc/version: %s", str)
	}
	return kernelVersionFromReleaseString(match[1])
}

func currentVersionUname() (uint32, error) {
	var buf syscall.Utsname
	if err := syscall.Uname(&buf); err != nil {
		return 0, err
	}
	releaseString := strings.Trim(utsnameStr(buf.Release[:]), "\x00")
	return kernelVersionFromReleaseString(releaseString)
}

func utsnameStr(in []int8) string {
	out := make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		if in[i] == 0 {
			break
		}
		out = append(out, byte(in[i]))
	}
	return string(out)
}

var releasePattern = regexp.MustCompile(`^(\d+)\.(\d+)(?:.(\d+))?.*$`)

// converts a release string with format 4.4.2[-1] to a kernel version number in LINUX_VERSION_CODE format.
// That is, for kernel "a.b.c", the version number will be (a<<16 + b<<8 + c)
func kernelVersionFromReleaseString(releaseString string) (uint32, error) {
	versionParts := releasePattern.FindStringSubmatch(releaseString)
	if len(versionParts) < 3 {
		return 0, fmt.Errorf("got invalid release version %q (expected format '4.3.2-1')", releaseString)
	}

	major, err := strconv.ParseUint(versionParts[1], 10, 8)
	if err != nil {
		return 0, err
	}

	minor, err := strconv.ParseUint(versionParts[2], 10, 8)
	if err != nil {
		return 0, err
	}

	// patch is optional
	var patch uint64
	if len(versionParts) >= 4 {
		patch, _ = strconv.ParseUint(versionParts[3], 10, 8)
	}

	// clamp patch/sublevel to 255 EARLY in 4.14.252 because they merged this too early:
	// https://github.com/torvalds/linux/commit/e131e0e880f942f138c4b5e6af944c7ddcd7ec96
	if major == 4 && minor == 14 && patch >= 252 {
		patch = 255
	}

	out := major*256*256 + minor*256 + patch
	return uint32(out), nil
}
