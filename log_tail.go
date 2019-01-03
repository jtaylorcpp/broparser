package broparser

import (
	"github.com/hpcloud/tail"
)

func FollowDNS(dnsfile string) *tail.Tail {
	tailer, err := tail.TailFile(dnsfile, tail.Config{Follow: true, MustExist: true})
	if err != nil {
		panic(err)
	}
	return tailer
}

func FollowConn(connfile string) *tail.Tail {
	tailer, err := tail.TailFile(connfile, tail.Config{Follow: true, MustExist: true})
	if err != nil {
		panic(err)
	}
	return tailer
}
