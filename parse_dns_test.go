package broparser

import (
	"testing"
)

func TestDNSParser(t *testing.T) {
	testDNSRecord := "1546109510.900653	C1Pith2CMQtfpWtnP9	192.168.1.13	47703	192.168.1.1	53	udp	58243 0.015960	google.com	1	C_INTERNET	1	A	0	NOERROR	F	F	T	T	0	172.217.3.110	41.000000	F"
	t.Logf("google dns log to parse: %s\n", testDNSRecord)
	record := ParseDNS(testDNSRecord)
	t.Logf("parsed google dns record: %v\n", record)

	testDNSRecord = "1546109517.448607	CU9S2r49EVy9ETA8bk	192.168.1.13	48329	192.168.1.1	53	udp	22344	0.007998	netflix.com	1	C_INTERNET	1	A	0	NOERROR	F	F	T	T	0	54.173.169.115,34.232.235.235,35.153.58.124,52.201.200.150,54.165.157.123,52.86.210.197,54.80.77.89,52.20.168.249	11.000000,11.000000,11.000000,11.000000,11.000000,11.000000,11.000000,11.000000	F"
	t.Logf("netflix dns log to parse: %s\n", testDNSRecord)
	record = ParseDNS(testDNSRecord)
	t.Logf("parsed netflix dns record: %v\n", record)
}
