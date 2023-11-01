// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfDatarec struct {
	RxPackets uint64
	RxBytes   uint64
}

type bpfEvent struct {
	Pid   uint32
	Comm  [80]uint8
	Token [4096]uint8
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	EnterOpenat *ebpf.ProgramSpec `ebpf:"enter_openat"`
	EnterRead   *ebpf.ProgramSpec `ebpf:"enter_read"`
	ExitOpenat  *ebpf.ProgramSpec `ebpf:"exit_openat"`
	ExitRead    *ebpf.ProgramSpec `ebpf:"exit_read"`
	XdpStats    *ebpf.ProgramSpec `ebpf:"xdp_stats"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	MapBuffAddrs *ebpf.MapSpec `ebpf:"map_buff_addrs"`
	MapFds       *ebpf.MapSpec `ebpf:"map_fds"`
	Tokens       *ebpf.MapSpec `ebpf:"tokens"`
	XdpStatsMap  *ebpf.MapSpec `ebpf:"xdp_stats_map"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	MapBuffAddrs *ebpf.Map `ebpf:"map_buff_addrs"`
	MapFds       *ebpf.Map `ebpf:"map_fds"`
	Tokens       *ebpf.Map `ebpf:"tokens"`
	XdpStatsMap  *ebpf.Map `ebpf:"xdp_stats_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.MapBuffAddrs,
		m.MapFds,
		m.Tokens,
		m.XdpStatsMap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	EnterOpenat *ebpf.Program `ebpf:"enter_openat"`
	EnterRead   *ebpf.Program `ebpf:"enter_read"`
	ExitOpenat  *ebpf.Program `ebpf:"exit_openat"`
	ExitRead    *ebpf.Program `ebpf:"exit_read"`
	XdpStats    *ebpf.Program `ebpf:"xdp_stats"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.EnterOpenat,
		p.EnterRead,
		p.ExitOpenat,
		p.ExitRead,
		p.XdpStats,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfeb.o
var _BpfBytes []byte
