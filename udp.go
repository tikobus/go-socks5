package socks5

import (
	"bytes"
	"fmt"
	"net"
)

// maxUDPDatagram is the largest UDP payload we relay; it matches the
// theoretical maximum IPv4 UDP datagram size.
const maxUDPDatagram = 65535

// unmarshalUDPHeader parses the SOCKS5 UDP request/reply header
// defined by RFC 1928:
//
//	RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA
//
// It returns the fragment number, the destination address, and the
// remaining payload.
func unmarshalUDPHeader(b []byte) (byte, *AddrSpec, []byte, error) {
	if len(b) < 4 {
		return 0, nil, nil, fmt.Errorf("socks: UDP header too short")
	}

	r := bytes.NewReader(b[3:])
	dest, err := readAddrSpec(r)
	if err != nil {
		return 0, nil, nil, err
	}

	consumed := len(b) - r.Len()
	return b[2], dest, b[consumed:], nil
}

// marshalUDPHeader prepends a SOCKS5 UDP header (with fragment zero) to
// a payload, addressed to the given destination.
func marshalUDPHeader(dst *AddrSpec, payload []byte) []byte {
	var addrType uint8
	var addrBody []byte
	switch {
	case dst.FQDN != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(dst.FQDN))}, dst.FQDN...)

	case dst.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(dst.IP.To4())

	default:
		addrType = ipv6Address
		addrBody = []byte(dst.IP.To16())
	}

	pkt := make([]byte, 0, 4+len(addrBody)+2+len(payload))
	pkt = append(pkt, 0, 0, 0, addrType) // RSV RSV FRAG(0)
	pkt = append(pkt, addrBody...)
	pkt = append(pkt, byte(dst.Port>>8), byte(dst.Port&0xff))
	pkt = append(pkt, payload...)
	return pkt
}

// relayBack reads datagrams from a connected destination socket and
// forwards them to the client with a SOCKS5 UDP header prepended. It
// returns when the destination socket is closed.
func relayBack(pc net.PacketConn, tconn *net.UDPConn, client *net.UDPAddr) {
	buf := make([]byte, maxUDPDatagram)
	for {
		n, err := tconn.Read(buf)
		if err != nil {
			return
		}
		dst, ok := tconn.RemoteAddr().(*net.UDPAddr)
		if !ok {
			return
		}
		spec := &AddrSpec{IP: dst.IP, Port: dst.Port}
		if _, err := pc.WriteTo(marshalUDPHeader(spec, buf[:n]), client); err != nil {
			return
		}
	}
}
