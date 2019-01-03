package broparser

import (
	"testing"
)

func TestConnParser(t *testing.T) {
	testConnRecord := "1546109510.896095	CA32lyRBwRuhXkQZ3	192.168.1.13	52045	192.168.1.1	53	udp	dns	0.018243	39	67	SF	-	-	0	Dd	1	67	1	95	(empty)"
	t.Logf("conn log to parse: %s\n", testConnRecord)
	record := ParseConn(testConnRecord)
	t.Logf("parsed conn record: %v\n", record)

	testConnRecord = "1546109510.284372	CjTbtq447FMcyYfSzl	192.168.1.7	57621	192.168.1.255	57621	udp	-	-	-	-	S0	-	-	0	D	1	68	0	0	(empty)"
	t.Logf("conn log to parse: %s\n", testConnRecord)
	record = ParseConn(testConnRecord)
	t.Logf("parsed conn record: %v\n", record)
}
