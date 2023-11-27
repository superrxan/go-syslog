package format

import (
	"bufio"
	"github.com/superrxan/go-syslog/internal/syslogparser"
	"time"
)

type LogParts map[string]interface{}

type LogParser interface {
	Parse() error
	Dump() LogParts
	Location(*time.Location)
}

type Format interface {
	GetParser([]byte) LogParser
	GetSplitFunc() bufio.SplitFunc
}

type parserWrapper struct {
	syslogparser.LogParser
}

func (w *parserWrapper) Dump() LogParts {
	return LogParts(w.LogParser.Dump())
}
