//go:build !androidgki

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

package module

import (
	"bytes"
	"context"
	"ecapture/assets"
	"ecapture/user/config"
	"ecapture/user/event"
	"fmt"
	"log"
	"math"
	"os"

	"errors"
	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

type PostgresModule struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
}

// init probe
func (postgresModule *PostgresModule) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	postgresModule.Module.Init(ctx, logger, conf)
	postgresModule.conf = conf
	postgresModule.Module.SetChild(postgresModule)
	postgresModule.eventMaps = make([]*ebpf.Map, 0, 2)
	postgresModule.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (postgresModule *PostgresModule) Start() error {
	// fetch ebpf assets
	var bpfFileName = postgresModule.geteBPFName("user/bytecode/postgres_kern.o")
	postgresModule.logger.Printf("%s\tBPF bytecode filename:%s\n", postgresModule.Name(), bpfFileName)

	byteBuf, err := assets.Asset("user/bytecode/postgres_kern.o")
	if err != nil {
		return fmt.Errorf("couldn't find asset")
	}

	// setup the managers
	err = postgresModule.setupManagers()
	if err != nil {
		return fmt.Errorf("postgres module couldn't find binPath %v.", err)
	}

	// initialize the bootstrap manager
	if err := postgresModule.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), postgresModule.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}

	// start the bootstrap manager
	if err := postgresModule.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v", err)
	}

	// 加载map信息，map对应events decode表。
	err = postgresModule.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (postgresModule *PostgresModule) setupManagers() error {
	postgresPath := postgresModule.conf.(*config.PostgresConfig).PostgresPath

	_, err := os.Stat(postgresPath)
	if err != nil {
		return err
	}

	attachFunc := postgresModule.conf.(*config.PostgresConfig).FuncName

	postgresModule.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uprobe/exec_simple_query",
				EbpfFuncName:     "postgres_query",
				AttachToFuncName: attachFunc,
				BinaryPath:       postgresPath,
			},
		},
		Maps: []*manager.Map{{Name: "events"}},
	}

	postgresModule.logger.Printf("Postgres, binary path: %s, FunctionName: %s\n", postgresPath, attachFunc)

	postgresModule.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,
		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}

	return nil
}

func (postgresModule *PostgresModule) Close() error {
	if err := postgresModule.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v.", err)
	}
	return postgresModule.Module.Close()
}

func (postgresModule *PostgresModule) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := postgresModule.eventFuncMaps[em]
	return fun, found
}

func (postgresModule *PostgresModule) initDecodeFun() error {
	// postgresEventsMap to hook
	postgresEventsMap, found, err := postgresModule.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map: events")
	}
	postgresModule.eventMaps = append(postgresModule.eventMaps, postgresEventsMap)
	postgresModule.eventFuncMaps[postgresEventsMap] = &event.PostgresEvent{}

	return nil
}

func (postgresModule *PostgresModule) Events() []*ebpf.Map {
	return postgresModule.eventMaps
}

func init() {
	mod := &PostgresModule{}
	mod.name = ModuleNamePostgres
	mod.mType = ProbeTypeUprobe
	Register(mod)
}
