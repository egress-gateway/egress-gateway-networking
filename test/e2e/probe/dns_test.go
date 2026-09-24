package main

import (
	"golang.org/x/net/dns/dnsmessage"
	"testing"
)

func TestDNSQuestionTypesAndEDNS(t *testing.T) {
	for _, kind := range []string{"A", "AAAA", "TXT", "SRV", "MX", "PTR", "NULL", "ANY"} {
		m, err := dnsQuestion("unique.origin.test", kind, true)
		if err != nil {
			t.Fatal(err)
		}
		b, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		var decoded dnsmessage.Message
		if err = decoded.Unpack(b); err != nil || len(decoded.Additionals) != 1 || len(b) < 900 {
			t.Fatalf("EDNS: %v, %d bytes", err, len(b))
		}
		decoded.Response = true
		if err = validateDNSReply(m, decoded); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDNSReplyCorrelation(t *testing.T) {
	m, _ := dnsQuestion("unique.origin.test", "A", false)
	for _, mutate := range []func(*dnsmessage.Message){func(r *dnsmessage.Message) { r.ID++ }, func(r *dnsmessage.Message) { r.Questions = nil }, func(r *dnsmessage.Message) {
		r.Questions = []dnsmessage.Question{{Name: dnsmessage.MustNewName("wrong.test."), Type: 1, Class: 1}}
	}, func(r *dnsmessage.Message) {
		r.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("wrong.test."), Type: 1, Class: 1}}}
	}} {
		r := m
		r.Response = true
		mutate(&r)
		if validateDNSReply(m, r) == nil {
			t.Fatal("unrelated reply accepted")
		}
	}
}
