package main

import (
	"github.com/k-sone/snmpgo"
)

type TrapListener struct {
	workers []*PipeWorker
}

func NewTrapListener(configs []PipeConfig) (*TrapListener, error) {
	workers := make([]*PipeWorker, 0, len(configs))
	for _, c := range configs {
		worker, err := NewPipeWorker(c)
		if err != nil {
			return nil, err
		}

		workers = append(workers, worker)
	}

	return &TrapListener{workers: workers}, nil
}

func (l *TrapListener) OnTRAP(trap *snmpgo.TrapRequest) {
	if trap.Error != nil {
		return
	}

	for _, w := range l.workers {
		if w.OID != "" {
			prefix, err := snmpgo.NewOid(w.OID)
			if err != nil {
				continue
			}

			varBinds := trap.Pdu.VarBinds().MatchBaseOids(prefix)
			if len(varBinds) == 0 {
				continue
			}
		}

		w.perform(trap)
		if w.Drop {
			break
		}
	}
}
