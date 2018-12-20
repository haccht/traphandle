package main

import (
	"flag"
	"log"

	"github.com/k-sone/snmpgo"
)

func Run(config TrapProxyConfig) error {
	server, err := snmpgo.NewTrapServer(snmpgo.ServerArguments{LocalAddr: config.Source.Address})
	if err != nil {
		return err
	}

	err = server.AddSecurity(&snmpgo.SecurityEntry{
		Version:   config.Source.Version.SNMPVersion,
		Community: config.Source.Community,
	})
	if err != nil {
		return err
	}

	listener, err := NewTrapListener(config.Pipe)
	if err != nil {
		return err
	}

	err = server.Serve(listener)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	var path = flag.String("config", "config.toml", "Path to the configuration file.")
	flag.Parse()

	config, err := ParseTOMLConfig(*path)
	if err != nil {
		log.Fatal(err)
	}

	if err = Run(config); err != nil {
		log.Fatal(err)
	}
}
