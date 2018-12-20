package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/k-sone/snmpgo"
)

type PipeWorker struct {
	queues []chan *snmpgo.TrapRequest
	PipeConfig
}

func NewPipeWorker(config PipeConfig) (*PipeWorker, error) {
	w := &PipeWorker{PipeConfig: config}
	w.queues = make([]chan *snmpgo.TrapRequest, 0, 3)

	if w.File.Path != "" {
		c, err := w.chFile()
		if err != nil {
			return nil, err
		}

		w.queues = append(w.queues, c)
	}

	if w.Exec.Command != "" {
		c, err := w.chExec()
		if err != nil {
			return nil, err
		}

		w.queues = append(w.queues, c)
	}

	if w.Forward.Address != "" {
		c, err := w.chForward()
		if err != nil {
			return nil, err
		}

		w.queues = append(w.queues, c)
	}

	return w, nil
}

func (w *PipeWorker) perform(trap *snmpgo.TrapRequest) {
	for _, queue := range w.queues {
		queue <- trap
	}
}

func (w *PipeWorker) chFile() (chan *snmpgo.TrapRequest, error) {
	c := make(chan *snmpgo.TrapRequest, 1000)

	fd, err := os.OpenFile(w.File.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	logger := log.New(fd, "", log.LstdFlags)

	go func() {
		defer fd.Close()

		for trap := range c {
			logger.Printf("%v %v", trap.Source, trap.Pdu)
		}
	}()

	return c, nil
}

func (w *PipeWorker) chExec() (chan *snmpgo.TrapRequest, error) {
	c := make(chan *snmpgo.TrapRequest, 1000)

	interval := w.Exec.Interval
	if interval == 0 {
		interval = 5
	}

	const format = "20060102150405"
	ticker := time.NewTicker(time.Duration(interval) * time.Second)

	go func() {
		var buffer []*snmpgo.TrapRequest
		var tmpfile *os.File

		for {
			select {
			case trap, ok := <-c:
				if !ok {
					ticker.Stop()
					return
				}

				buffer = append(buffer, trap)
			case <-ticker.C:
				if len(buffer) == 0 {
					continue
				}

				filename := fmt.Sprintf("snmptrapd%s_", time.Now().Format(format))
				tmpfile, _ = ioutil.TempFile("", filename)
				tmpfile.Chmod(0666)

				for _, trap := range buffer {
					tmpfile.WriteString(fmt.Sprintf(
						"{\"Source\": \"%s\", \"VarBinds\": %s}\n",
						trap.Source, trap.Pdu.VarBinds().String()))
				}

				tmpfile.Close()
				exec.Command(w.Exec.Command, tmpfile.Name()).Run()

				buffer = nil
				os.Remove(tmpfile.Name())
			}

		}
	}()

	return c, nil
}

func (w *PipeWorker) chForward() (chan *snmpgo.TrapRequest, error) {
	c := make(chan *snmpgo.TrapRequest, 1000)

	forwarder, err := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Address:   w.Forward.Address,
		Version:   w.Forward.Version.SNMPVersion,
		Community: w.Forward.Community,
	})
	if err != nil {
		return nil, err
	}

	if err = forwarder.Open(); err != nil {
		return nil, err
	}

	go func() {
		defer forwarder.Close()

		for trap := range c {
			forwarder.V2Trap(trap.Pdu.VarBinds())
		}
	}()

	return c, nil
}
