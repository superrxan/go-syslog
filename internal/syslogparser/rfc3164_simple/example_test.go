package rfc3164_simple

import (
	"fmt"
	"github.com/superrxan/go-syslog/internal/syslogparser/rfc3164"
)

func ExampleNewParser() {
	b := "<34>2018-01-12T22:14:15+00:00 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
	buff := []byte(b)

	p := rfc3164.NewParser(buff)
	err := p.Parse()
	if err != nil {
		panic(err)
	}

	fmt.Println(p.Dump())
}
