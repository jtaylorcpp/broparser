package broparser

import (
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
)

/*
FROM BRO dns.log
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	 rejected
#types	time	string	addr	port	addr	port	enum	count	interval	string	count	string	count	string	count	string	bool	bool	bool	bool	count	vector[string]	vector[interval]	bool
*/

// first regex does not take into account vectors
//const dnsregex = `(\d+\.\d+)[ \t]+([0-9A-Za-z]+)[ \t](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[ \t](\d+)[ \t](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[ \t](\d+)[ \t](udp|tcp)[ \t](\d+)[ \t](\d+\.\d+)[ \t]([a-zA-Z0-9\.:]+)[ \t](\d+)[ \t]([A-Z_]+)[ \t](\d+)[ \t](\w+)[ \t](\d+)[ \t](\w+)[ \t](\w+)[ \t](\w+)[ \t](\w+)[ \t](\w+)[ \t](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[ \t](\d+\.\d+)[ \t](\w+)`
//const dnsregex = `(\d+\.\d+)[ \t]+([0-9A-Za-z]+)[ \t](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[ \t](\d+)[ \t](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[ \t](\d+)[ \t](udp|tcp)[ \t](\d+)[ \t](\d+\.\d+)[ \t]([a-zA-Z0-9\.:]+)[ \t](\d+)[ \t]([A-Z_]+)[ \t](\d+)[ \t](\w+)[ \t](\d+)[ \t](\w+)[ \t](\w+)[ \t](\w+)[ \t](\w+)[ \t](\w+)[ \t]((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\,?)+)[ \t]((\d+\.\d+\,?)+)[ \t](\w+)`
//const dnsregex = `(\d+\.\d+)[ \t]+([0-9A-Za-z]+)[ \t](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[ \t](\d+)[ \t](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[ \t](\d+)[ \t](udp|tcp)[ \t](\d+)[ \t](\d+\.\d+)[ \t]([a-zA-Z0-9\.:]+)[ \t](\d+)[ \t]([A-Z_]+)[ \t](\d+)[ \t](\w+)[ \t](\d+)[ \t](\w+)[ \t](\w+)[ \t](\w+)[ \t](\w+)[ \t](\w+)[ \t](\d+)[ \t]((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\,?)+)[ \t]((\d+\.\d+\,?)+)[ \t](\w+)`

// bellow allows a fqdn to also be a answer in the dns record
const dnsregex = `(\d+\.\d+)[ \t]+([0-9A-Za-z]+)[ \t](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[ \t](\d+)[ \t](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[ \t](\d+)[ \t](udp|tcp)[ \t](\d+)[ \t](\d+\.\d+)[ \t]([a-zA-Z0-9\.:]+)[ \t](\d+)[ \t]([A-Z_]+)[ \t](\d+)[ \t](\w+)[ \t](\d+)[ \t](\w+)[ \t](\w+)[ \t](\w+)[ \t](\w+)[ \t](\w+)[ \t](\d+)[ \t](([a-zA-Z0-9\.]\,?)+)[ \t]((\d+\.\d+\,?)+)[ \t](\w+)`

var dnsparser *regexp.Regexp

func init() {
	dnsparser = regexp.MustCompile(dnsregex)
}

type DNSRecord struct {
	gorm.Model
	TimeStamp  time.Time
	UID        string
	ClientAddr string
	ClientPort uint16
	ServerAddr string
	ServerPort uint16
	Protocol   string
	RoundTrip  float32
	Query      string
	Type       string
	Answers    []DNSAnswer `gorm:"many2many:dns_record_answers"`
}

type DNSAnswer struct {
	gorm.Model
	Address string
	TTL     uint32
}

func ParseDNS(logline string) DNSRecord {
	log.Printf("parsing dns log: %s\n", logline)
	parsed := dnsparser.FindAllStringSubmatch(logline, -1)
	log.Printf("parsed dns log: %v\n", parsed)

	if len(parsed) == 0 {
		return DNSRecord{}
	}

	/*for idx, parsedElem := range parsed[0] {
		log.Printf("%v|%v: %v\n", idx, parsedElem == logline, parsedElem)
	}*/

	returnRecord := DNSRecord{}
	for regexidx, majormatches := range parsed {
		if majormatches[0] == logline {
			log.Printf("DNS record regex found major match and index %d\n", regexidx)
			for idx, elem := range majormatches {
				switch idx {
				case 1:
					//timestamp
					times := strings.Split(elem, ".")
					sec, err := strconv.ParseInt(times[0], 10, 64)
					if err != nil {
						panic(err)
					}
					nsec, err := strconv.ParseInt(times[1], 10, 64)
					if err != nil {
						panic(err)
					}
					returnRecord.TimeStamp = time.Unix(sec, nsec)
				case 2:
					//uid
					returnRecord.UID = elem
				case 3:
					//client ip
					returnRecord.ClientAddr = elem
				case 4:
					//client port
					port64, err := strconv.ParseUint(elem, 10, 16)
					if err != nil {
						panic(err)
					}
					returnRecord.ClientPort = uint16(port64)
				case 5:
					// server ip
					returnRecord.ServerAddr = elem
				case 6:
					// server port
					port64, err := strconv.ParseUint(elem, 10, 16)
					if err != nil {
						panic(err)
					}
					returnRecord.ServerPort = uint16(port64)
				case 7:
					// protocol
					returnRecord.Protocol = elem
				case 9:
					// round trip
					rtf64, err := strconv.ParseFloat(elem, 32)
					if err != nil {
						panic(err)
					}
					returnRecord.RoundTrip = float32(rtf64)
				case 10:
					// query
					returnRecord.Query = elem
				case 14:
					// type
					returnRecord.Type = elem
				case 22:
					// answers
					// TTLS per answer are idx 24
					returnRecord.Answers = []DNSAnswer{}
					addresses := strings.Split(elem, ",")
					ttls := strings.Split(majormatches[24], ",")
					//log.Printf("parsing answers <%v> and ttls<%v>\n", addresses, ttls)
					for addrIdx, addr := range addresses {
						ttlf64, err := strconv.ParseFloat(ttls[addrIdx], 64)
						if err != nil {
							panic(err)
						}
						ttl64 := int64(ttlf64)
						returnRecord.Answers = append(returnRecord.Answers, DNSAnswer{Address: addr, TTL: uint32(ttl64)})
					}

				}
			}
		}
	}

	return returnRecord
}
