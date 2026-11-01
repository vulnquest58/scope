// Package enforce provides the L3 DNS enforcement layer.
package enforce

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/vulnquest58/scope/internal/decide"
)

// Resolver is a local DNS server that filters queries via the scope engine.
type Resolver struct {
	Engine   *decide.Engine
	Upstream string // e.g. "1.1.1.1:53"
	Level    int
}

// DNS message constants.
const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
	dnsQR       = 0x8000 // response bit
	dnsRCODE    = 0x000F // rcode mask
	dnsRCODE_NXDOMAIN = 3
	dnsRCODE_REFUSED  = 5
)

// HandleDNS processes a raw DNS query packet and returns a response packet.
// HandleDNS returns NXDOMAIN for denied names and REFUSED for unsupported query types.
func (r *Resolver) HandleDNS(query []byte, client net.Addr) ([]byte, error) {
	if len(query) < 12 {
		return nil, fmt.Errorf("dns: packet too short")
	}

	// Parse header.
	id := binary.BigEndian.Uint16(query[0:2])
	flags := binary.BigEndian.Uint16(query[2:4])
	qdCount := binary.BigEndian.Uint16(query[4:6])

	// Must be a query (QR bit = 0).
	if flags&dnsQR != 0 {
		return nil, fmt.Errorf("dns: not a query")
	}
	if qdCount == 0 {
		return dnsRefused(id, query), nil
	}

	// Parse first question.
	qname, qtype, offset, err := parseQuestion(query, 12)
	if err != nil {
		return dnsRefused(id, query), nil
	}
	_ = offset

	// Only handle A and AAAA.
	if qtype != dnsTypeA && qtype != dnsTypeAAAA {
		return dnsRefused(id, query), nil
	}

	// Make decision.
	d := r.Engine.Decide(context.Background(), qname, r.Level)
	if d.Verdict == decide.Deny {
		return dnsNXDOMAIN(id, query), nil
	}

	// Forward to upstream.
	resp, err := r.forwardUpstream(query)
	if err != nil {
		// Fail-closed: if upstream fails, return NXDOMAIN.
		return dnsNXDOMAIN(id, query), nil
	}
	return resp, nil
}

// ListenUDP starts a UDP DNS server on addr.
func (r *Resolver) ListenUDP(addr string) error {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	buf := make([]byte, 512)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go func(q []byte, src net.Addr) {
			resp, err := r.HandleDNS(q, src)
			if err != nil || resp == nil {
				return
			}
			conn.WriteTo(resp, src) //nolint:errcheck
		}(query, src)
	}
}

// forwardUpstream sends the raw DNS query to the upstream resolver.
func (r *Resolver) forwardUpstream(query []byte) ([]byte, error) {
	upstream := r.Upstream
	if upstream == "" {
		upstream = "1.1.1.1:53"
	}
	conn, err := net.DialTimeout("udp", upstream, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// dnsNXDOMAIN builds a DNS response with NXDOMAIN (rcode=3).
func dnsNXDOMAIN(id uint16, query []byte) []byte {
	return dnsErrorResp(id, query, dnsRCODE_NXDOMAIN)
}

// dnsRefused builds a DNS response with REFUSED (rcode=5).
func dnsRefused(id uint16, query []byte) []byte {
	return dnsErrorResp(id, query, dnsRCODE_REFUSED)
}

// dnsErrorResp builds a minimal DNS error response.
func dnsErrorResp(id uint16, query []byte, rcode int) []byte {
	resp := make([]byte, 12)
	binary.BigEndian.PutUint16(resp[0:2], id)
	// QR=1 (response), AA=0, RD=1 (copy), RA=0, RCODE=rcode
	flags := uint16(dnsQR | 0x0100 | rcode)
	binary.BigEndian.PutUint16(resp[2:4], flags)
	// QDCOUNT: copy from query if available
	if len(query) >= 6 {
		binary.BigEndian.PutUint16(resp[4:6], binary.BigEndian.Uint16(query[4:6]))
	}
	// ANCOUNT, NSCOUNT, ARCOUNT = 0
	binary.BigEndian.PutUint16(resp[6:8], 0)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	// Append question section from query.
	if len(query) > 12 {
		resp = append(resp, query[12:]...)
	}
	return resp
}

// parseQuestion parses a DNS question at offset and returns (qname, qtype, newOffset, err).
func parseQuestion(msg []byte, offset int) (string, uint16, int, error) {
	name, offset, err := parseName(msg, offset)
	if err != nil {
		return "", 0, 0, err
	}
	if offset+4 > len(msg) {
		return "", 0, 0, fmt.Errorf("dns: short question")
	}
	qtype := binary.BigEndian.Uint16(msg[offset : offset+2])
	return name, qtype, offset + 4, nil
}

// parseName parses a DNS wire-format name starting at offset.
func parseName(msg []byte, offset int) (string, int, error) {
	var name []byte
	visited := make(map[int]bool)
	for {
		if offset >= len(msg) {
			return "", 0, fmt.Errorf("dns: name out of bounds")
		}
		if visited[offset] {
			return "", 0, fmt.Errorf("dns: name loop")
		}
		visited[offset] = true

		length := int(msg[offset])
		if length == 0 {
			offset++
			break
		}
		// Pointer compression.
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(msg) {
				return "", 0, fmt.Errorf("dns: pointer out of bounds")
			}
			ptr := int(binary.BigEndian.Uint16(msg[offset:offset+2]) & 0x3FFF)
			offset += 2
			sub, _, err := parseName(msg, ptr)
			if err != nil {
				return "", 0, err
			}
			if len(name) > 0 {
				name = append(name, '.')
			}
			name = append(name, sub...)
			return string(name), offset, nil
		}
		offset++
		if offset+length > len(msg) {
			return "", 0, fmt.Errorf("dns: label out of bounds")
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, msg[offset:offset+length]...)
		offset += length
	}
	return string(name), offset, nil
}

