// Some of this was copied from a Go test icmpraw_test.go:
//
// Copyright 2009 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trace

import (
	"bytes"
	"code.google.com/p/go.net/ipv4"
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"time"
)


type resolveIPAddrTest struct {
	net     string
	litAddr string
	addr    *net.IPAddr
	err     error
}

var supportsIPv6 = false

const (
	icmpv4EchoRequest = 8
	icmpv4EchoReply   = 0
	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129
)

// icmpMessage represents an ICMP message.
type icmpMessage struct {
	Type     int             // type
	Code     int             // code
	Checksum int             // checksum
	Body     icmpMessageBody // body
}

// icmpMessageBody represents an ICMP message body.
type icmpMessageBody interface {
	Len() int
	Marshal() ([]byte, error)
}

func nextIcmpPacket(netClass, laddr string) *ipv4.Header {
	for {
		c, err := net.ListenPacket(netClass, laddr)
		if err != nil {
			log.Fatalf("Could not listen: %v", err)
		}
		defer c.Close()
		if err != nil {
			log.Fatalf("Invalid connection: %v", err)
		}
		ipv4RawConn, err := ipv4.NewRawConn(c)
		if err != nil {
			log.Fatalf("NewRawConn: %v", err)
		}
		err = ipv4RawConn.SetDeadline(time.Now().Add(2000 * time.Millisecond))
		if err != nil {
			log.Fatalf("NewRawConn: %v", err)
		}
		b := make([]byte, 1024)
		h, p, cm, errRead := ipv4RawConn.ReadFrom(b)
//		log.Printf("RawConn.ReadFrom: header: %+v - (all %d bytes): %v", h, len(b))
//		log.Printf(" .. (packet %d bytes) - cm: %v", len(p), cm)
		header, err:= ipv4.ParseHeader(b)
		if err != nil {
			log.Printf("ParseHeader failed : %v", err)
		}
//		log.Printf("IP header: %v", header)
//		log.Printf("IP Source: %v", header.Src)
//		log.Printf("IP Dest: %v", header.Dst)
		if errRead != nil {
			log.Printf("Could not read body")
			log.Printf("RawConn.ReadFrom: header: %+v - (all %d bytes): %v", h, len(b))
			log.Printf(" .. (packet %d bytes) - cm: %v", len(p), cm)
		}
		return header
	}
}


func Hop(netClass, laddr, raddr string, hops int) *ipv4.Header {

		afnet, _, err := parseNetwork(netClass)
		if err != nil {
			log.Fatalf("parseNetwork failed: %v", err)
		}
		if afnet == "ip6" && !supportsIPv6 {
			log.Fatalf("IPv6 not supported")
		}

		lAddr, err := net.ResolveIPAddr("ip", laddr)
		if err != nil {
			log.Fatalf("Resolve failed: %v", err)
		}
		rAddr, err := net.ResolveIPAddr("ip", raddr)
		if err != nil {
			log.Fatalf("Resolve failed: %v", err)
		}

//		log.Printf("Connecting to: %v", raddr)
		c, err := net.DialIP(netClass, lAddr, rAddr)
		if err != nil {
			log.Fatalf("Dial failed: %v", err)
		}
		c.SetDeadline(time.Now().Add(100 * time.Millisecond))
		defer c.Close()
		ipv4Conn := ipv4.NewConn(c)
		err = ipv4Conn.SetTTL(hops)
		if err != nil {
                        // error handling
			log.Fatalf("SetTTL failed: %v", err)
                }
		typ := icmpv4EchoRequest
		if afnet == "ip6" {
			typ = icmpv6EchoRequest
		}
		xid, xseq := os.Getpid()&0xffff, hops+1
		b, err := (&icmpMessage{
			Type: typ, Code: 0,
			Body: &icmpEcho{
				ID: xid, Seq: xseq,
				Data: bytes.Repeat([]byte("Go Go Gadget Ping!!!"), 3),
			},
		}).Marshal()
		if err != nil {
			log.Fatalf("icmpMessage.Marshal failed: %v", err)
		}

		n, err := c.Write(b)
		if err != nil {
			log.Fatalf("Conn.Write failed: %v / %d", err, n)
		}
//		log.Printf("Conn.Write wrote: %d bytes (%v)", n, b)
		rh := nextIcmpPacket("ip4:icmp", "0.0.0.0")
		return rh
}

func ipv4Payload(b []byte) []byte {
	if len(b) < 20 {
		return b
	}
	hdrlen := int(b[0]&0x0f) << 2
	return b[hdrlen:]
}
func ipv4Header(b []byte) []byte {
	if len(b) < 20 {
		return []byte{}
	}
	hdrlen := int(b[0]&0x0f) << 2
	return b[:hdrlen]
}

// Marshal returns the binary enconding of the ICMP echo request or
// reply message m.
func (m *icmpMessage) Marshal() ([]byte, error) {
	b := []byte{byte(m.Type), byte(m.Code), 0, 0}
	if m.Body != nil && m.Body.Len() != 0 {
		mb, err := m.Body.Marshal()
		if err != nil {
			return nil, err
		}
		b = append(b, mb...)
	}
	switch m.Type {
	case icmpv6EchoRequest, icmpv6EchoReply:
		return b, nil
	}
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	// Place checksum back in header; using ^= avoids the
	// assumption the checksum bytes are zero.
	b[2] ^= byte(^s & 0xff)
	b[3] ^= byte(^s >> 8)
	return b, nil
}

// parseICMPMessage parses b as an ICMP message.
func parseICMPMessage(b []byte) (*icmpMessage, error) {
	msglen := len(b)
	if msglen < 4 {
		return nil, errors.New("message too short")
	}
	m := &icmpMessage{Type: int(b[0]), Code: int(b[1]), Checksum: int(b[2])<<8 | int(b[3])}
	if msglen > 4 {
		var err error
		switch m.Type {
		case icmpv4EchoRequest, icmpv4EchoReply, icmpv6EchoRequest, icmpv6EchoReply:
			m.Body, err = parseICMPEcho(b[4:])
			if err != nil {
				return nil, err
			}
		}
	}
	return m, nil
}

// imcpEcho represenets an ICMP echo request or reply message body.
type icmpEcho struct {
	ID   int    // identifier
	Seq  int    // sequence number
	Data []byte // data
}

func (p *icmpEcho) Len() int {
	if p == nil {
		return 0
	}
	return 4 + len(p.Data)
}

// Marshal returns the binary enconding of the ICMP echo request or
// reply message body p.
func (p *icmpEcho) Marshal() ([]byte, error) {
	b := make([]byte, 4+len(p.Data))
	b[0], b[1] = byte(p.ID>>8), byte(p.ID&0xff)
	b[2], b[3] = byte(p.Seq>>8), byte(p.Seq&0xff)
	copy(b[4:], p.Data)
	return b, nil
}

// parseICMPEcho parses b as an ICMP echo request or reply message
// body.
func parseICMPEcho(b []byte) (*icmpEcho, error) {
	bodylen := len(b)
	p := &icmpEcho{ID: int(b[0])<<8 | int(b[1]), Seq: int(b[2])<<8 | int(b[3])}
	if bodylen > 4 {
		p.Data = make([]byte, bodylen-4)
		copy(p.Data, b[4:])
	}
	return p, nil
}

//-----------------

// loopbackInterface returns an available logical network interface
// for loopback tests.  It returns nil if no suitable interface is
// found.
func loopbackInterface() *net.Interface {
        ift, err := net.Interfaces()
        if err != nil {
                return nil
        }
        for _, ifi := range ift {
                if ifi.Flags&net.FlagLoopback != 0 && ifi.Flags&net.FlagUp != 0 {
                        return &ifi
                }
        }
        return nil
}

func zoneToString(zone int) string {
        if zone == 0 {
                return ""
        }
        if ifi, err := net.InterfaceByIndex(zone); err == nil {
                return ifi.Name
        }
        return itod(uint(zone))
}

//dummy
func parseNetwork(net string) (afnet string, proto int, err error) {
		afnet = "ip4"
		if strings.Contains(net, "ip6") {
			afnet = "ip6"
		}
	return afnet, 0, nil
}

// Convert i to decimal string.
func itod(i uint) string {
        if i == 0 {
                return "0"
        }

        // Assemble decimal in reverse order.
        var b [32]byte
        bp := len(b)
        for ; i > 0; i /= 10 {
                bp--
                b[bp] = byte(i%10) + '0'
        }

        return string(b[bp:])
}

