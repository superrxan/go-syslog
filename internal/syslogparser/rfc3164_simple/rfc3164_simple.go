package rfc3164_simple

import (
	"github.com/superrxan/go-syslog/internal/syslogparser"
	"strings"
	"time"
)

type Parser struct {
	buff     []byte
	cursor   int
	l        int
	priority syslogparser.Priority
	version  int
	header   header
	message  rfc3164message
	location *time.Location

	cutCursor int
	sb        strings.Builder
}

type header struct {
	timestamp time.Time
	hostname  string
}

type rfc3164message struct {
	tag     string
	content string
}

func NewParser(buff []byte) *Parser {
	return &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}
}

func (p *Parser) Location(location *time.Location) {
	p.location = location
}

func (p *Parser) Parse() error {
	p.cutCursor = p.cursor
	pri, err := p.parsePriority()
	if err != nil {
		// RFC3164 sec 4.3.3
		p.priority = syslogparser.Priority{13, syslogparser.Facility{Value: 1}, syslogparser.Severity{Value: 5}}
		content, err := p.parseContent()
		p.header.timestamp = time.Now().Round(time.Second)
		if err != syslogparser.ErrEOL {
			return err
		}
		p.message = rfc3164message{content: content}
		return nil
	}

	msg := rfc3164message{}
	hdr := header{}

	p.sb.Reset()
	p.parseTimestamp()
	p.parseHostname()

	p.cutCursor = p.cursor
	tag, _ := p.parseTag()
	msg.tag = tag

	content, _ := p.parseContent()
	msg.content = content

	p.priority = pri
	p.version = syslogparser.NO_VERSION
	p.header = hdr
	p.message = msg

	return nil
}

func (p *Parser) Dump() syslogparser.LogParts {
	return syslogparser.LogParts{
		"timestamp": p.header.timestamp,
		"hostname":  p.header.hostname,
		"tag":       p.message.tag,
		"content":   p.message.content,
		"priority":  p.priority.P,
		"facility":  p.priority.F.Value,
		"severity":  p.priority.S.Value,
	}
}

func (p *Parser) parsePriority() (syslogparser.Priority, error) {
	return syslogparser.ParsePriority(p.buff, &p.cursor, p.l)
}

// skip this part
func (p *Parser) parseTimestamp() {
	//<Priority>TIMESTAMP hostname tag[PID]: MSG
	//skip the TIMESTAMP part
	for ; p.cursor < p.l; p.cursor++ {
		p.sb.WriteByte(p.buff[p.cursor])
		if p.buff[p.cursor] == ' ' {
			p.cursor++
			break
		}
	}
}

func (p *Parser) parseHostname() {
	//<Priority>TIMESTAMP hostname tag[PID]: MSG
	//skip the host part
	for ; p.cursor < p.l; p.cursor++ {
		if p.buff[p.cursor] == ' ' {
			p.cursor++
			break
		}
	}
}

// http://tools.ietf.org/html/rfc3164#section-4.1.3
func (p *Parser) parseTag() (string, error) {
	var b byte
	var endOfTag bool
	var bracketOpen bool
	var tag []byte
	var err error
	var found bool

	from := p.cursor

	for {
		if p.cursor == p.l {
			// no tag found, reset cursor for content
			p.cursor = from
			return "", nil
		}

		b = p.buff[p.cursor]
		bracketOpen = (b == '[')
		endOfTag = (b == ':' || b == ' ')

		// XXX : parse PID ?
		if bracketOpen {
			tag = p.buff[from:p.cursor]
			found = true
		}

		if endOfTag {
			if !found {
				tag = p.buff[from:p.cursor]
				found = true
			}

			p.cursor++
			break
		}

		p.cursor++
	}

	if (p.cursor < p.l) && (p.buff[p.cursor] == ' ') {
		p.cursor++
	}

	return string(tag), err
}

func (p *Parser) parseContent() (string, error) {
	if p.cursor > p.l {
		return p.sb.String(), syslogparser.ErrEOL
	}

	content := p.buff[p.cutCursor:p.l]
	p.sb.Write(content)

	return p.sb.String(), syslogparser.ErrEOL
}
