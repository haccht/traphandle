package main

import (
	"log"
	"os"
	"os/exec"

	"github.com/k-sone/snmpgo"
)

type TrapListener struct {
	ps []PipeConfig
	cs []chan *snmpgo.TrapRequest
}

func dispatch(pi PipeConfig, ch chan *snmpgo.TrapRequest) {
	var err error
	var logger *log.Logger
	var command *exec.Cmd
	var forwarder *snmpgo.SNMP

	if pi.File.Path != "" {
		file, err := os.OpenFile(pi.File.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal(err)
		}

		logger = log.New(file, "", log.LstdFlags)
	}

	if pi.Exec.Command != "" {
		command = exec.Command(pi.Exec.Command)
	}

	if pi.Forward.Address != "" {
		forwarder, err = snmpgo.NewSNMP(snmpgo.SNMPArguments{
			Address:   pi.Forward.Address,
			Version:   pi.Forward.Version.SNMPVersion,
			Community: pi.Forward.Community,
		})
		if err != nil {
			log.Fatal(err)
		}

		if err = forwarder.Open(); err != nil {
			log.Fatal(err)
		}

		defer forwarder.Close()
	}

	for trap := range ch {
		if logger != nil {
			logger.Printf("%v %v", trap.Source, trap.Pdu)
		}

		if command != nil {
			command.Run()
		}

		if forwarder != nil {
			forwarder.V2Trap(trap.Pdu.VarBinds())
		}
	}
}

func NewTrapListener(pipes []PipeConfig) *TrapListener {
	cs := []chan *snmpgo.TrapRequest{}
	for _, pi := range pipes {
		ch := make(chan *snmpgo.TrapRequest)
		cs = append(cs, ch)

		go dispatch(pi, ch)
	}

	return &TrapListener{
		ps: pipes,
		cs: cs,
	}
}

func (tl *TrapListener) OnTRAP(trap *snmpgo.TrapRequest) {
	if trap.Error != nil {
		return
	}

	size := len(tl.cs)
	for i := 0; i < size; i++ {
		pi := tl.ps[i]
		ch := tl.cs[i]

		prefix, _ := snmpgo.NewOid(pi.OID)
		varBinds := trap.Pdu.VarBinds().MatchBaseOids(prefix)
		if len(varBinds) == 0 {
			continue
		}

		ch <- trap

		if pi.Drop {
			break
		}
	}
}
