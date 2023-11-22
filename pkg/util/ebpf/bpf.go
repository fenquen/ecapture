// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ebpf

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

type UnameInfo struct {
	SysName    string
	Nodename   string
	Release    string
	Version    string
	Machine    string
	Domainname string
}

func getOSUnamer() (*UnameInfo, error) {
	u := unix.Utsname{}
	e := unix.Uname(&u)
	if e != nil {
		return nil, e
	}
	ui := UnameInfo{}
	ui.SysName = charsToString(u.Sysname)
	ui.Nodename = charsToString(u.Nodename)
	ui.Release = charsToString(u.Release)
	ui.Version = charsToString(u.Version)
	ui.Machine = charsToString(u.Machine)
	ui.Domainname = charsToString(u.Domainname)

	return &ui, nil
}

func charsToString(ca [65]byte) string {
	s := make([]byte, len(ca))
	var lens int
	for ; lens < len(ca); lens++ {
		if ca[lens] == 0 {
			break
		}
		s[lens] = uint8(ca[lens])
	}
	return string(s[0:lens])
}

// from internal/btf/bpf.go
// checkKernelBTF attempts to load the raw vmlinux BTF blob at
// /sys/kernel/btf/vmlinux and falls back to scanning the file system
// for vmlinux ELFs.
func checkKernelBTF() (bool, error) {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")

	// if exist ,return true
	if err == nil {
		return true, nil
	}

	return findVMLinux()
}

// scans multiple well-known paths for vmlinux kernel images.
func findVMLinux() (bool, error) {
	kv, err := getOSUnamer()
	if err != nil {
		return false, err
	}
	release := kv.Release

	for _, loc := range locations {
		_, err := os.Stat(fmt.Sprintf(loc, release))
		if err != nil {
			continue
		}
		return true, nil
	}
	return false, err
}

func IsEnableBTF() (bool, error) {
	found, e := checkKernelBTF()
	if e == nil && found {
		return true, nil
	}

	var KernelConfig = make(map[string]string)

	KernelConfig, e = GetSystemConfig()
	if e != nil {
		return false, e
	}

	bc, found := KernelConfig["CONFIG_DEBUG_INFO_BTF"]
	if !found {
		return false, nil
	}

	//如果有，在判断配置项的值
	if bc != "y" {
		// 没有开启
		return false, nil
	}

	return true, nil
}

// check BPF CONFIG
func IsEnableBPF() (bool, error) {
	var e error
	var KernelConfig = make(map[string]string)

	KernelConfig, e = GetSystemConfig()
	if e != nil {
		return false, e
	}

	for _, item := range []string{"CONFIG_BPF", "CONFIG_UPROBES", "CONFIG_ARCH_SUPPORTS_UPROBES"} {
		bc, found := KernelConfig[item]
		if !found {
			// 没有这个配置项
			return false, fmt.Errorf("Config not found,  item:%s.", item)
		}

		//如果有，在判断配置项的值
		if bc != "y" {
			// 没有开启
			return false, fmt.Errorf("Config disabled, item :%s.", item)
		}
	}

	return true, nil
}
