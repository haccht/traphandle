package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/soniah/gosnmp"
)

func main() {
	config, err := NewTrapHandleConfig()
	if err != nil {
		log.Fatal(err)
	}

	handlers := []*TrapHandler{}
	for _, h := range config.Handle {
		handler, err := NewTrapHandler(h)
		if err != nil {
			log.Fatal(err)
		}

		handlers = append(handlers, handler)
	}

	listener := gosnmp.NewTrapListener()
	listener.Params = gosnmp.Default
	listener.Params.Version = config.Source.Version.SnmpVersion
	listener.Params.Community = config.Source.Community

	listener.OnNewTrap = func(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
		varBinds := packet.Variables

		for _, handler := range handlers {
			var matchBaseOID bool
			for _, varBind := range varBinds {
				matchBaseOID = matchBaseOID || strings.HasPrefix(varBind.Name, handler.OID)
			}

			if matchBaseOID {
				handler.Handle(packet, addr)
				if handler.Drop {
					break
				}
			}
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		<-sig
		for _, h := range handlers {
			h.Close()
		}

		listener.Close()
	}()

	if err = listener.Listen(config.Source.Address); err != nil {
		log.Fatal(err)
	}
}
