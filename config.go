package main

import (
	"flag"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/soniah/gosnmp"
)

type TrapHandleConfig struct {
	Source SNMPConfig
	Handle []HandleConfig
}

type version struct {
	gosnmp.SnmpVersion
}

func (v *version) UnmarshalText(text []byte) error {
	switch string(text) {
	case "1":
		v.SnmpVersion = gosnmp.Version1
	case "2c":
		v.SnmpVersion = gosnmp.Version2c
	case "3":
		v.SnmpVersion = gosnmp.Version3
	default:
		return fmt.Errorf("Illegal Version, value `%s`", text)
	}

	return nil
}

type SNMPConfig struct {
	Address   string
	Version   version
	Community string
}

type HandleConfig struct {
	OID  string
	Drop bool
	Log  LogConfig
	Cmd  CmdConfig
	Fwd  SNMPConfig
}

type LogConfig struct {
	Prefix  string
	Logfile string
}

type CmdConfig struct {
	Command  string
	Interval int
}

func NewTrapHandleConfig() (TrapHandleConfig, error) {
	var config TrapHandleConfig
	var configPath string

	flag.StringVar(&configPath, "config", "config.toml", "Path to the configuration file.")
	flag.Parse()

	_, err := toml.DecodeFile(configPath, &config)
	if err != nil {
		return config, err
	}

	return config, nil
}
