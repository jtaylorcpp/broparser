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
FROM Bro conn.log
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
*/
//const connregex = `(\d+\.\d+)[ \t]([a-zA-Z0-9]+)[ \t](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[ \t](\d+)[ \t](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[ \t](\d+)[ \t]([a-z]+)[ \t](\w+|-)[ \t](\d+\.\d+)[ \t](\d+)[ \t](\d+)[ \t]([A-Z0-3]+)[ \t](T|F|-)[ \t](T|F|-)[ \t](\d+)[ \t]([a-zA-Z-]+)[ \t](\d+)[ \t](\d+)[ \t](\d+)[ \t](\d+)[ \t](\(empty\)|[a-zA-Z\.,])`
const connregex = `(\d+\.\d+)[ \t]([a-zA-Z0-9]+)[ \t](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[ \t](\d+)[ \t](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[ \t](\d+)[ \t]([a-z]+)[ \t](\w+|-)[ \t]((\d+\.\d+)|-)[ \t](\d+|-)[ \t](\d+|-)[ \t]([A-Z0-3]+)[ \t](T|F|-)[ \t](T|F|-)[ \t](\d+)[ \t]([a-zA-Z-]+)[ \t](\d+)[ \t](\d+)[ \t](\d+)[ \t](\d+)[ \t](\(empty\)|[a-zA-Z\.,])`

var connparser *regexp.Regexp

func init() {
	connparser = regexp.MustCompile(connregex)
}

type ConnRecord struct {
	gorm.Model

	TimeStamp        time.Time
	UID              string
	ClientAddr       string
	ClientPort       uint16
	ServerAddr       string
	ServerPort       uint16
	Protocol         string
	Service          string
	Duration         float32
	ClientBytes      uint64
	ServerBytes      uint64
	State            string
	LocalOriginating bool
	LocalResponding  bool
	History          string
}

func ParseConn(logline string) ConnRecord {
	log.Printf("parsing conn log: %s\n", logline)
	parsed := connparser.FindAllStringSubmatch(logline, -1)
	log.Printf("parsed conn log: %v\n", parsed)

	/*for idx, parsedElem := range parsed[0] {
		log.Printf("%v|%v: %v\n", idx, parsedElem == logline, parsedElem)
	}*/

	returnRecord := ConnRecord{}
	for regexidx, majormatches := range parsed {
		if majormatches[0] == logline {
			log.Printf("Conn record regex found major match and index %d\n", regexidx)
			for idx, elem := range majormatches {
				switch idx {
				case 1:
					//time stamp
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
					//client addr
					returnRecord.ClientAddr = elem
				case 4:
					// client port
					p64, err := strconv.ParseUint(elem, 10, 16)
					if err != nil {
						panic(err)
					}
					returnRecord.ClientPort = uint16(p64)
				case 5:
					//server addr
					returnRecord.ServerAddr = elem
				case 6:
					//server port
					p64, err := strconv.ParseUint(elem, 10, 16)
					if err != nil {
						panic(err)
					}
					returnRecord.ServerPort = uint16(p64)
				case 7:
					//protocol
					returnRecord.Protocol = elem
				case 8:
					//service
					returnRecord.Service = elem
				case 9:
					//duration
					if elem == "-" {
						returnRecord.Duration = float32(0)
					} else {
						f64, err := strconv.ParseFloat(elem, 32)
						if err != nil {
							panic(err)
						}
						returnRecord.Duration = float32(f64)
					}
				case 11:
					//client bytes
					if elem == "-" {
						returnRecord.ClientBytes = uint64(0)
					} else {
						b64, err := strconv.ParseUint(elem, 10, 64)
						if err != nil {
							panic(err)
						}
						returnRecord.ClientBytes = b64
					}
				case 12:
					//server bytes
					if elem == "-" {
						returnRecord.ServerBytes = uint64(0)
					} else {
						b64, err := strconv.ParseUint(elem, 10, 64)
						if err != nil {
							panic(err)
						}
						returnRecord.ServerBytes = b64
					}
				case 13:
					//connection state
					returnRecord.State = elem
				case 14:
					// local originated
					switch elem {
					case "T":
						returnRecord.LocalOriginating = true
					case "F", "-":
						returnRecord.LocalOriginating = false
					default:
						returnRecord.LocalOriginating = false
					}
				case 15:
					//local responded
					switch elem {
					case "T":
						returnRecord.LocalOriginating = true
					case "F", "-":
						returnRecord.LocalOriginating = false
					default:
						returnRecord.LocalOriginating = false
					}
				case 17:
					//history
					returnRecord.History = elem

				}
			}

		}
	}

	return returnRecord
}
