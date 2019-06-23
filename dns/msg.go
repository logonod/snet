package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
)

type RType uint16

func (t RType) String() string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"

	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	default:
		return fmt.Sprintf("UNKNOWN %d", t)
	}
}

type ARecord struct {
	IP  net.IP
	TTL uint32
}

func (a *ARecord) String() string {
	return fmt.Sprintf("ip: %v, ttl: %d", a.IP, a.TTL)
}

func NewARecord(ip []byte, ttl uint32) *ARecord {
	return &ARecord{net.IPv4(ip[0], ip[1], ip[2], ip[3]), ttl}
}

type DNSMsg struct {
	ID       uint16
	qr       int    // query or answer
	QDCount  uint16 // query count
	ANCount  uint16 // answer count
	QDomain  string // query domain
	QType    RType  // query type
	QClass   uint16
	ARecords []*ARecord // returned A record list
}

func (m *DNSMsg) String() string {
	t := "query"
	if m.qr == 1 {
		t = "answer"
	}
	return fmt.Sprintf(`%s id:%d qdcount:%d ancount: %d  query: %s qtype: %s qclass: %d arecords: %s`,
		t, m.ID, m.QDCount, m.ANCount, m.QDomain, m.QType, m.QClass, m.ARecords)
}

func GetEmptyDNSResp(queryData []byte) []byte {
	resp := queryData
	// modify header to convert query to response
	resp[2] = 0x81 // set QR bit to 1, means it's a response
	resp[3] = 0x80
	return resp
}

func GetBlockDNSResp(queryData []byte, queryDomain string) []byte {
	// TODO ugly, need to rewrite dns parser
	labelLen := 0
	for _, label := range strings.Split(queryDomain, ".") {
		labelLen += 1 + len(label)
	}
	labelLen++ // domain endswith 0x00

	answerOffset := 12 + labelLen + 4
	// 16 is length of a single answer field: name pointer + type + class + ttl + len + ip
	resp := make([]byte, answerOffset+16)
	copy(resp, queryData[:answerOffset])
	// modify header to convert query to response
	resp[2] = 0x81 // set QR bit to 1, means it's a response
	resp[3] = 0x80
	resp[7] = 0x01  // set answer count field to 1
	resp[9] = 0x00  // set authority rrs to 0
	resp[11] = 0x00 // set additional rrs to 0
	// make name pointer ref name in query field
	resp[answerOffset] = 0xc0
	resp[answerOffset+1] = 0x0c
	// type A
	resp[answerOffset+3] = 0x01
	// class 1
	resp[answerOffset+5] = 0x01
	// tll 100
	resp[answerOffset+9] = 0x64
	// data len
	resp[answerOffset+11] = 0x4
	// ip addr: 127.0.0.1
	resp[answerOffset+12] = 0x7f
	resp[answerOffset+15] = 0x1
	return resp
}

func (m *DNSMsg) IsQuery() bool {
	return m.qr == 0
}

func (m *DNSMsg) IsAnswer() bool {
	return m.qr == 1
}

func (m *DNSMsg) Equal(t *DNSMsg) error {
	if m.ID != t.ID {
		return errors.New("dns id not match")
	}
	if m.qr != t.qr {
		return errors.New("dns qr not match")
	}
	if m.QDCount != t.QDCount {
		return errors.New("dns qdcount not match")
	}
	if m.ANCount != t.ANCount {
		return errors.New("dns ancount not match")
	}
	if m.QDomain != t.QDomain {
		return errors.New("dns qdomain not match")
	}
	if m.QType != t.QType {
		return errors.New("dns qtype not match")
	}
	if m.QClass != t.QClass {
		return errors.New("dns qclass not match")
	}
	if len(m.ARecords) != len(t.ARecords) {
		return errors.New("a records number not match")
	}
	for i, s := range m.ARecords {
		t := t.ARecords[i]
		if !reflect.DeepEqual(s, t) {
			return fmt.Errorf("%dst A record not match", i)
		}
	}
	return nil
}

func NewDNSMsg(data []byte) (*DNSMsg, error) {
	if len(data) == 0 {
		return nil, errors.New("empty dns msg")
	}
	id := binary.BigEndian.Uint16(data[:2])
	isAnswer := false
	if data[2]&0x80 == 0x80 {
		isAnswer = true
	}
	qdcount := binary.BigEndian.Uint16(data[4:6])
	// multi query is allowed(qdcount >1), but I didn't see this in real life(just don't handle it)!
	if qdcount > 1 {
		return nil, errors.New("mutil query in a dns message found")
	}
	ancount := binary.BigEndian.Uint16(data[6:8])
	body := data[12:]
	queryDomainLabels := []string{}
	var qtype uint16
	var qclass uint16
	for {
		// parse question
		offset := 0
		labelLen := int(body[0])
		offset++ // 1 byte label length
		label := body[offset : offset+labelLen]
		offset += labelLen
		queryDomainLabels = append(queryDomainLabels, string(label))
		if body[offset+1] == 0x0 {
			// finish parse question domain
			body = body[offset+1:]
			qtype = binary.BigEndian.Uint16(body[:2])
			body = body[2:]
			qclass = binary.BigEndian.Uint16(body[:2])
			body = body[2:]
			break
		}
		// continue to next label
		body = body[offset:]
	}
	queryDomain := strings.Join(queryDomainLabels, ".")
	arecords := []*ARecord{}
	if isAnswer {
		if len(body) == 0 {
			return &DNSMsg{ID: id, QDCount: qdcount, ANCount: ancount, qr: 1,
				QDomain: queryDomain, QType: RType(qtype), QClass: qclass, ARecords: arecords}, nil
		}
		// parse answer
		if len(body) < 12 {
			// at least Pointer(2) + Type(2) + Class(2) + TTL(4) + RLEN(2) = 12
			return nil, errors.New("Bad answer message")
		}
		for i := 0; i < int(ancount); i++ {
			c1 := body[0]
			c2 := body[1]
			body = body[2:]
			switch c1 & 0xC0 {
			case 0x0:
				if c1 != 0 || c2 != 0 {
					// Normal dns server's response NAME field always a pointer to existing data(NAME in QUESTION)
					// if top 2 bytes not equal 0, it's an uncompressed msg.
					return nil, errors.New("Maybe this dns server didn't compress response data? domain:" + queryDomain)
				}
			case 0xC0:
				atype := RType(binary.BigEndian.Uint16(body[:2]))
				body = body[4:] // skip TYPE + CLASS
				ttl := binary.BigEndian.Uint32(body[:4])
				body = body[4:] // skip ttl
				rdLen := binary.BigEndian.Uint16(body[:2])
				body = body[2:] // skip rdLen
				if atype.String() != "A" {
					// only intereseted in A type, skip left rdata for other records
					body = body[rdLen:]
					continue
				}
				rdata := body[:rdLen]
				arecords = append(arecords, NewARecord(rdata, ttl))
				body = body[rdLen:] // skip rdata
			default:
				// 0x80 and 0x40 are reversed bits, shouldn't appear here
				return nil, errors.New("bad message")
			}
		}
	}
	qr := 0
	if isAnswer {
		qr = 1
	}
	return &DNSMsg{
		ID: id, QDCount: qdcount, ANCount: ancount,
		qr:      qr,
		QDomain: queryDomain,
		QType:   RType(qtype), QClass: qclass,
		ARecords: arecords}, nil
}
