package main

import (
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/k-sone/snmpgo"
)

type SNMPTrapdConfig struct {
	Source SNMPConfig
	Pipe   []PipeConfig
}

type version struct {
	snmpgo.SNMPVersion
}

func (v *version) UnmarshalText(text []byte) error {
	switch string(text) {
	case "1":
		v.SNMPVersion = snmpgo.V1
	case "2c":
		v.SNMPVersion = snmpgo.V2c
	case "3":
		v.SNMPVersion = snmpgo.V3
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

type PipeConfig struct {
	OID     string
	Drop    bool
	File    FileConfig
	Exec    ExecConfig
	Forward SNMPConfig
}

type FileConfig struct {
	Path string
}

type ExecConfig struct {
	Command  string
	Interval int
}

func ParseTOMLConfig(path string) (SNMPTrapdConfig, error) {
	var config SNMPTrapdConfig

	_, err := toml.DecodeFile(path, &config)
	if err != nil {
		return config, err
	}

	return config, nil
}
