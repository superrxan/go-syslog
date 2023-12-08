package rfc3164_simple

import (
	"github.com/superrxan/go-syslog/internal/syslogparser"
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

// Hooks up gocheck into the gotest runner.
func Test(t *testing.T) { TestingT(t) }

type Rfc3164TestSuite struct {
}

var (
	_ = Suite(&Rfc3164TestSuite{})
)

func (s *Rfc3164TestSuite) TestParser_Valid(c *C) {
	buff := []byte("<34>2018-01-12T22:14:15+00:00 mymachine very.large.syslog.message.tag: 'su root' failed for lonvick on /dev/pts/8")

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	c.Assert(p, DeepEquals, expectedP)

	err := p.Parse()
	c.Assert(err, IsNil)

	obtained := p.Dump()
	expected := syslogparser.LogParts{
		"timestamp": time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
		"hostname":  "",
		"tag":       "very.large.syslog.message.tag",
		"content":   "2018-01-12T22:14:15+00:00 very.large.syslog.message.tag: 'su root' failed for lonvick on /dev/pts/8",
		"priority":  34,
		"facility":  4,
		"severity":  2,
	}

	c.Assert(obtained, DeepEquals, expected)
}

func (s *Rfc3164TestSuite) TestParser_ValidTagPid(c *C) {
	buff := []byte("<34>2018-01-12T22:14:15+00:00 mymachine very.large.syslog.message.tag[23]: 'su root' failed for lonvick on /dev/pts/8")

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	c.Assert(p, DeepEquals, expectedP)

	err := p.Parse()
	c.Assert(err, IsNil)

	obtained := p.Dump()
	expected := syslogparser.LogParts{
		"timestamp": time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
		"hostname":  "",
		"tag":       "very.large.syslog.message.tag",
		"content":   "2018-01-12T22:14:15+00:00 very.large.syslog.message.tag[23]: 'su root' failed for lonvick on /dev/pts/8",
		"priority":  34,
		"facility":  4,
		"severity":  2,
	}

	c.Assert(obtained, DeepEquals, expected)
}

func (s *Rfc3164TestSuite) TestParser_TrimTimestamp(c *C) {
	buff := []byte(`<34>2018-01-12T22:14:15+00:00 mymachine very.large.syslog.message.tag[23]: time="2018-01-12T22:14:15+00:00" level="info" msg='su root' failed for lonvick on /dev/pts/8`)

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	c.Assert(p, DeepEquals, expectedP)

	err := p.Parse()
	c.Assert(err, IsNil)

	obtained := p.Dump()
	expected := syslogparser.LogParts{
		"timestamp": time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
		"hostname":  "",
		"tag":       "very.large.syslog.message.tag",
		"content":   `2018-01-12T22:14:15+00:00 very.large.syslog.message.tag[23]: level="info" msg='su root' failed for lonvick on /dev/pts/8`,
		"priority":  34,
		"facility":  4,
		"severity":  2,
	}

	c.Assert(obtained, DeepEquals, expected)
}

func (s *Rfc3164TestSuite) TestParser_ValidNoTag(c *C) {
	buff := []byte("<34>2018-01-12T22:14:15+00:00 mymachine singleword")

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	c.Assert(p, DeepEquals, expectedP)

	err := p.Parse()
	c.Assert(err, IsNil)

	obtained := p.Dump()
	expected := syslogparser.LogParts{
		"timestamp": time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
		"hostname":  "",
		"tag":       "",
		"content":   "2018-01-12T22:14:15+00:00 singleword",
		"priority":  34,
		"facility":  4,
		"severity":  2,
	}

	c.Assert(obtained, DeepEquals, expected)
}

// RFC 3164 section 4.3.2
func (s *Rfc3164TestSuite) TestParser_NoTimestamp(c *C) {
	buff := []byte("<14>INFO    leaving (1) step postscripts")

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	c.Assert(p, DeepEquals, expectedP)

	err := p.Parse()
	c.Assert(err, IsNil)

	obtained := p.Dump()

	expected := syslogparser.LogParts{
		"timestamp": time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
		"hostname":  "",
		"tag":       "",
		"content":   "INFO   leaving (1) step postscripts",
		"priority":  14,
		"facility":  1,
		"severity":  6,
	}

	c.Assert(obtained, DeepEquals, expected)
}

// RFC 3164 section 4.3.3
func (s *Rfc3164TestSuite) TestParser_NoPriority(c *C) {
	buff := []byte("2018-01-12T22:14:15+00:00 Testing no priority")

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	c.Assert(p, DeepEquals, expectedP)

	err := p.Parse()
	c.Assert(err, IsNil)
	obtained := p.Dump()

	now := time.Now()
	obtained["timestamp"] = now

	expected := syslogparser.LogParts{
		"timestamp": now,
		"hostname":  "",
		"tag":       "",
		"content":   "2018-01-12T22:14:15+00:00 Testing no priority",
		"priority":  13,
		"facility":  1,
		"severity":  5,
	}

	c.Assert(obtained, DeepEquals, expected)
}

func (s *Rfc3164TestSuite) TestParseTag_Pid(c *C) {
	buff := []byte("apache2[10]:")
	tag := "apache2"

	s.assertTag(c, tag, buff, len(buff), nil)
}

func (s *Rfc3164TestSuite) TestParseTag_NoPid(c *C) {
	buff := []byte("apache2:")
	tag := "apache2"

	s.assertTag(c, tag, buff, len(buff), nil)
}

func (s *Rfc3164TestSuite) TestParseTag_TrailingSpace(c *C) {
	buff := []byte("apache2: ")
	tag := "apache2"

	s.assertTag(c, tag, buff, len(buff), nil)
}

func (s *Rfc3164TestSuite) TestParseTag_NoTag(c *C) {
	buff := []byte("apache2")
	tag := ""

	s.assertTag(c, tag, buff, 0, nil)
}

func (s *Rfc3164TestSuite) TestParseContent_Valid(c *C) {
	buff := []byte(" foo bar baz quux ")
	content := string(buff)

	p := NewParser(buff)
	obtained, err := p.parseContent()
	c.Assert(err, Equals, syslogparser.ErrEOL)
	c.Assert(obtained, Equals, content)
}

func (s *Rfc3164TestSuite) BenchmarkParseTag(c *C) {
	buff := []byte("apache2[10]:")

	p := NewParser(buff)

	for i := 0; i < c.N; i++ {
		_, err := p.parseTag()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func (s *Rfc3164TestSuite) assertTag(c *C, t string, b []byte, expC int, e error) {
	p := NewParser(b)
	obtained, err := p.parseTag()
	c.Assert(obtained, Equals, t)
	c.Assert(p.cursor, Equals, expC)
	c.Assert(err, Equals, e)
}
