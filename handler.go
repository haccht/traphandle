package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/soniah/gosnmp"
)

const datetimeFormat = "20060102150405"

var (
	snmpTrapOIDRegexp = regexp.MustCompile(`^\.1\.3\.6\.1\.6\.3\.1\.1\.4\.1\.0`)
	snmpTrapsRegexp   = regexp.MustCompile(`^\.1\.3\.6\.1\.6\.3\.1\.1\.5.(\d+)`)
	enterprisesRegexp = regexp.MustCompile(`^(\.1\.3\.6\.1\.4\.1\.\d+)+(\.0)?\.(\d+)$`)
)

type TrapHandler struct {
	queues []chan *snmpTrap
	HandleConfig
}

type snmpTrap struct {
	source *net.UDPAddr
	packet *gosnmp.SnmpPacket
}

func (t *snmpTrap) String() string {
	varBinds := make([]string, len(t.packet.Variables))
	for i, v := range t.packet.Variables {
		value := v.Value

		var asn1ber string
		switch v.Type {
		case gosnmp.EndOfContents:
			asn1ber = "EndOfContents/UnknownType"
		case gosnmp.Boolean:
			asn1ber = "Boolean"
		case gosnmp.Integer:
			asn1ber = "Integer"
		case gosnmp.BitString:
			asn1ber = "BitString"
		case gosnmp.OctetString:
			asn1ber = "OctetString"
			value = string(v.Value.([]byte))
		case gosnmp.Null:
			asn1ber = "Null"
		case gosnmp.ObjectIdentifier:
			asn1ber = "ObjectIdentifier"
		case gosnmp.ObjectDescription:
			asn1ber = "ObjectDescription"
		case gosnmp.IPAddress:
			asn1ber = "IPAddress"
		case gosnmp.Counter32:
			asn1ber = "Counter32"
		case gosnmp.Gauge32:
			asn1ber = "Gauge32"
		case gosnmp.TimeTicks:
			asn1ber = "TimeTicks"
		case gosnmp.Opaque:
			asn1ber = "Opaque"
		case gosnmp.NsapAddress:
			asn1ber = "NsapAddress"
		case gosnmp.Counter64:
			asn1ber = "Counter64"
		case gosnmp.Uinteger32:
			asn1ber = "Uinteger32"
		case gosnmp.OpaqueFloat:
			asn1ber = "OpaqueFloat"
		case gosnmp.OpaqueDouble:
			asn1ber = "OpaqueDouble"
		case gosnmp.NoSuchObject:
			asn1ber = "NoSuchObject"
		case gosnmp.NoSuchInstance:
			asn1ber = "NoSuchInstance"
		case gosnmp.EndOfMibView:
			asn1ber = "EndOfMibView"
		}

		varBinds[i] = fmt.Sprintf(
			`{"Oid": "%s", "Type": "%v", "Value": "%v"}`,
			v.Name, asn1ber, value)
	}

	var pduType string
	switch t.packet.PDUType {
	case gosnmp.Sequence:
		pduType = "Sequence"
	case gosnmp.GetRequest:
		pduType = "GetRequest"
	case gosnmp.GetNextRequest:
		pduType = "GetNextRequest"
	case gosnmp.GetResponse:
		pduType = "GetResponse"
	case gosnmp.SetRequest:
		pduType = "SetRequest"
	case gosnmp.Trap:
		pduType = "Trap"
	case gosnmp.GetBulkRequest:
		pduType = "GetBulkRequest"
	case gosnmp.InformRequest:
		pduType = "InformRequest"
	case gosnmp.SNMPv2Trap:
		pduType = "SNMPv2Trap"
	case gosnmp.Report:
		pduType = "Report"
	}

	var errStatus string
	switch t.packet.Error {
	case gosnmp.NoError:
		errStatus = "NoError"
	case gosnmp.TooBig:
		errStatus = "TooBig"
	case gosnmp.NoSuchName:
		errStatus = "NoSuchName"
	case gosnmp.BadValue:
		errStatus = "BadValue"
	case gosnmp.ReadOnly:
		errStatus = "ReadOnly"
	case gosnmp.GenErr:
		errStatus = "GenErr"
	case gosnmp.NoAccess:
		errStatus = "NoAccess"
	case gosnmp.WrongType:
		errStatus = "WrongType"
	case gosnmp.WrongLength:
		errStatus = "WrongLength"
	case gosnmp.WrongEncoding:
		errStatus = "WrongEncoding"
	case gosnmp.WrongValue:
		errStatus = "WrongValue"
	case gosnmp.NoCreation:
		errStatus = "NoCreation"
	case gosnmp.InconsistentValue:
		errStatus = "InconsistentValue"
	case gosnmp.ResourceUnavailable:
		errStatus = "ResourceUnavailable"
	case gosnmp.CommitFailed:
		errStatus = "CommitFailed"
	case gosnmp.UndoFailed:
		errStatus = "UndoFailed"
	case gosnmp.AuthorizationError:
		errStatus = "AuthorizationError"
	case gosnmp.NotWritable:
		errStatus = "NotWritable"
	case gosnmp.InconsistentName:
		errStatus = "InconsistentName"
	}

	return fmt.Sprintf(
		`{"Source": "%s", "Type": "%v", "RequestId": "%d", "Error": "%v", "ErrorIndex": "%d", "VarBinds": [%s]}`,
		t.source, pduType, t.packet.RequestID, errStatus, t.packet.ErrorIndex, strings.Join(varBinds, ", "))
}

func makeLogQueue(config LogConfig) (chan *snmpTrap, error) {
	c := make(chan *snmpTrap, 1000)

	fd, err := os.OpenFile(config.Logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	logger := log.New(fd, config.Prefix, log.LstdFlags)

	go func() {
		defer fd.Close()

		for trap := range c {
			logger.Printf(trap.String())
		}
	}()

	return c, nil
}

func makeCmdQueue(config CmdConfig) (chan *snmpTrap, error) {
	c := make(chan *snmpTrap, 4096)

	if config.Interval == 0 {
		config.Interval = 5
	}

	ticker := time.NewTicker(time.Duration(config.Interval) * time.Second)
	buffer := make([]*snmpTrap, 0, 4096)

	go func() {
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

				filename := fmt.Sprintf("traphandle_%s_", time.Now().Format(datetimeFormat))

				tempfile, _ := ioutil.TempFile("", filename)
				tempfile.Chmod(0666)

				for _, trap := range buffer {
					tempfile.WriteString(trap.String() + "\n")
				}
				buffer = nil

				tempfile.Close()
				exec.Command(config.Command, tempfile.Name()).Run()

				os.Remove(tempfile.Name())
			}

		}
	}()

	return c, nil
}

func makeFwdQueue(config SNMPConfig) (chan *snmpTrap, error) {
	c := make(chan *snmpTrap, 1000)

	if config.Version.SnmpVersion != gosnmp.Version1 {
		return nil, fmt.Errorf("Fowarding traps with SNMP version %v is not allowed", config.Version.SnmpVersion)
	}

	hostaddr, port, err := net.SplitHostPort(config.Address)
	if err != nil {
		return nil, fmt.Errorf("Forwarding address must be in the format '<IPv4_ADDRESS>:<PORT>'")
	}

	port_num, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("Forwarding address must be in the format '<IPv4_ADDRESS>:<PORT>'")
	}

	client := &gosnmp.GoSNMP{
		Target:    hostaddr,
		Port:      uint16(port_num),
		Community: config.Community,
		Version:   config.Version.SnmpVersion,
		Timeout:   time.Duration(2) * time.Second,
		Retries:   3,
	}

	if err = client.Connect(); err != nil {
		return nil, err
	}

	go func() {
		defer client.Conn.Close()

		for trap := range c {
			var newTrap gosnmp.SnmpTrap

			switch trap.packet.Version {
			case gosnmp.Version1:
				newTrap = trap.packet.SnmpTrap
			case gosnmp.Version2c:
				var varBinds []gosnmp.SnmpPDU
				var enterprise string
				var genericTrap, specificTrap int

				for _, v := range trap.packet.Variables {
					if v.Type == gosnmp.TimeTicks {
						v.Value = uint32(v.Value.(uint))
					}

					varBinds = append(varBinds, v)
					if snmpTrapOIDRegexp.MatchString(v.Name) {
						value := v.Value.(string)
						if sm := snmpTrapsRegexp.FindStringSubmatch(value); len(sm) > 0 {
							enterprise = value
							genericTrap, _ = strconv.Atoi(sm[1])
							specificTrap = 0
							break
						} else if sm := enterprisesRegexp.FindStringSubmatch(value); len(sm) > 0 {
							enterprise = sm[1]
							genericTrap = 6
							specificTrap, _ = strconv.Atoi(sm[3])
							break
						}
					}
				}

				agentAddr, _, _ := net.SplitHostPort(trap.source.String())
				newTrap = gosnmp.SnmpTrap{
					Variables:    varBinds,
					Enterprise:   enterprise,
					AgentAddress: agentAddr,
					GenericTrap:  genericTrap,
					SpecificTrap: specificTrap,
				}
			}

			if _, err := client.SendTrap(newTrap); err != nil {
				log.Printf("SendTrap err: %v", err)
			}
		}
	}()

	return c, nil
}

func NewTrapHandler(config HandleConfig) (*TrapHandler, error) {
	h := &TrapHandler{HandleConfig: config}
	h.queues = make([]chan *snmpTrap, 0, 3)

	if h.Log.Logfile != "" {
		queue, err := makeLogQueue(h.Log)
		if err != nil {
			return nil, err
		}

		h.queues = append(h.queues, queue)
	}

	if h.Cmd.Command != "" {
		queue, err := makeCmdQueue(h.Cmd)
		if err != nil {
			return nil, err
		}

		h.queues = append(h.queues, queue)
	}

	if h.Fwd.Address != "" {
		queue, err := makeFwdQueue(h.Fwd)
		if err != nil {
			return nil, err
		}

		h.queues = append(h.queues, queue)
	}

	return h, nil
}

func (w *TrapHandler) Handle(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	trap := &snmpTrap{addr, packet}
	for _, queue := range w.queues {
		queue <- trap
	}
}

func (w *TrapHandler) Close() {
	for _, queue := range w.queues {
		close(queue)
	}
}
