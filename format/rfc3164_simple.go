package format

import (
	"bufio"
	"github.com/superrxan/go-syslog/internal/syslogparser/rfc3164_simple"
)

type RFC3164_SIMPLE struct{}

func (f *RFC3164_SIMPLE) GetParser(line []byte) LogParser {
	return &parserWrapper{rfc3164_simple.NewParser(line)}
}

func (f *RFC3164_SIMPLE) GetSplitFunc() bufio.SplitFunc {
	return nil
}
