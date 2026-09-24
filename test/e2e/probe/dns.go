package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type dnsObservation struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Type       uint16    `json:"type"`
	Transport  string    `json:"transport"`
	Target     string    `json:"target"`
	Started    time.Time `json:"started"`
	Finished   time.Time `json:"finished"`
	Attempted  bool      `json:"attempted"`
	Sent       bool      `json:"sent"`
	Received   bool      `json:"received"`
	Correlated bool      `json:"correlated"`
	RCODE      string    `json:"rcode"`
	Answers    []string  `json:"answers"`
	Local      string    `json:"local,omitempty"`
	Error      string    `json:"error,omitempty"`
}

func dnsQuestion(name, kind string, edns bool) (dnsmessage.Message, error) {
	types := map[string]dnsmessage.Type{"A": 1, "AAAA": 28, "TXT": 16, "SRV": 33, "MX": 15, "PTR": 12, "NULL": 10, "ANY": 255}
	t, ok := types[kind]
	if !ok {
		return dnsmessage.Message{}, fmt.Errorf("unknown DNS type %q", kind)
	}
	n, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return dnsmessage.Message{}, err
	}
	var id [2]byte
	if _, err = rand.Read(id[:]); err != nil {
		return dnsmessage.Message{}, err
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: n, Type: t, Class: dnsmessage.ClassINET}}}
	if edns {
		m.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232}, Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 12, Data: make([]byte, 900)}}}}}
	}
	return m, nil
}

func validateDNSReply(question, response dnsmessage.Message) error {
	if !response.Response || response.ID != question.ID || len(response.Questions) != 1 || response.Questions[0] != question.Questions[0] {
		return errors.New("DNS response does not match transaction and question")
	}
	for _, rr := range response.Answers {
		if rr.Header.Name != question.Questions[0].Name || rr.Header.Class != dnsmessage.ClassINET {
			return errors.New("unrelated DNS answer")
		}
		if rr.Header.Type != question.Questions[0].Type && rr.Header.Type != dnsmessage.TypeCNAME && question.Questions[0].Type != dnsmessage.TypeALL {
			return errors.New("unexpected DNS answer type")
		}
	}
	return nil
}

func dnsProbe(ctx context.Context, f *flag.FlagSet, args []string) (result error) {
	name := f.String("query", "", "DNS question")
	kind := f.String("qtype", "A", "DNS record type")
	transport := f.String("transport", "udp", "udp or tcp")
	target := f.String("target", "", "resolver host:port; default from resolv.conf")
	id := f.String("id", "", "case correlation")
	edns := f.Bool("edns", false, "include EDNS padding")
	timeout := f.Duration("timeout", 8*time.Second, "bounded single exchange")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *name == "" || *id == "" || (*transport != "udp" && *transport != "tcp") || *timeout <= 0 {
		return errors.New("query, id, transport and positive timeout required")
	}
	if *target == "" {
		b, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return err
		}
		for line := range strings.SplitSeq(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "nameserver" {
				*target = net.JoinHostPort(fields[1], "53")
				break
			}
		}
		if *target == "" {
			return errors.New("no resolver configured")
		}
	}
	m, err := dnsQuestion(*name, *kind, *edns)
	if err != nil {
		return err
	}
	b, err := m.Pack()
	if err != nil {
		return err
	}
	o := dnsObservation{ID: *id, Name: m.Questions[0].Name.String(), Type: uint16(m.Questions[0].Type), Transport: *transport, Target: *target, Started: time.Now().UTC(), Attempted: true}
	defer func() {
		o.Finished = time.Now().UTC()
		if result != nil {
			o.Error = result.Error()
		}
		emit(o)
	}()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, *transport, *target)
	if err != nil {
		return err
	}
	defer c.Close()
	o.Local = c.LocalAddr().String()
	deadline, _ := ctx.Deadline()
	if err = c.SetDeadline(deadline); err != nil {
		return err
	}
	if *transport == "tcp" {
		b = append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)
	}
	if _, err = c.Write(b); err != nil {
		return err
	}
	o.Sent = true
	if *transport == "tcp" {
		var size [2]byte
		if _, err = io.ReadFull(c, size[:]); err != nil {
			return err
		}
		b = make([]byte, binary.BigEndian.Uint16(size[:]))
		_, err = io.ReadFull(c, b)
	} else {
		b = make([]byte, 65535)
		var n int
		n, err = c.Read(b)
		b = b[:n]
	}
	if err != nil {
		return err
	}
	o.Received = true
	var reply dnsmessage.Message
	if err = reply.Unpack(b); err != nil {
		return err
	}
	if err = validateDNSReply(m, reply); err != nil {
		return err
	}
	o.Correlated = true
	o.RCODE = reply.RCode.String()
	for _, rr := range reply.Answers {
		switch v := rr.Body.(type) {
		case *dnsmessage.AResource:
			o.Answers = append(o.Answers, net.IP(v.A[:]).String())
		case *dnsmessage.AAAAResource:
			o.Answers = append(o.Answers, net.IP(v.AAAA[:]).String())
		case *dnsmessage.CNAMEResource:
			o.Answers = append(o.Answers, v.CNAME.String())
		default:
			o.Answers = append(o.Answers, fmt.Sprintf("%v", rr.Body))
		}
	}
	return nil
}
