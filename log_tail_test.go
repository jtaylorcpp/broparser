package broparser

import (
	"testing"
)

func TestDNSTail(t *testing.T) {
	dnstailer := FollowDNS("./logs/dns.log")

	defer dnstailer.Cleanup()

	const dnscount = 3
	count := 0
	for count < dnscount {
		line := <-dnstailer.Lines
		dnsrecord := ParseDNS(line.Text)
		if dnsrecord.UID != "" {
			t.Logf("dns record: %v", dnsrecord)
			count += 1
		}
	}
}

func TestConnTail(t *testing.T) {
	conntailer := FollowConn("./logs/conn.log")

	defer conntailer.Cleanup()

	const conncount = 3
	count := 0

	for count < conncount {
		line := <-conntailer.Lines
		connrecord := ParseConn(line.Text)
		if connrecord.UID != "" {
			t.Logf("conn record: %v\n", connrecord)
			count += 1
		}
	}
}
