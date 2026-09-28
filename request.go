package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"
)

const (
	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3)
	ipv4Address      = uint8(1)
	fqdnAddress      = uint8(3)
	ipv6Address      = uint8(4)
)

const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

var (
	unrecognizedAddrType = fmt.Errorf("Unrecognized address type")
)

// AddressRewriter is used to rewrite a destination transparently
type AddressRewriter interface {
	Rewrite(ctx context.Context, request *Request) (context.Context, *AddrSpec)
}

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		if a.IP != nil {
			return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
		}
		return fmt.Sprintf("%s:%d", a.FQDN, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// Address returns a string suitable to dial; prefer returning IP-based
// address, fallback to FQDN
func (a AddrSpec) Address() string {
	if len(a.IP) > 0 {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

// A Request represents request received by a server
type Request struct {
	// Protocol version
	Version uint8
	// Requested command
	Command uint8
	// AuthContext provided during negotiation
	AuthContext *AuthContext
	// AddrSpec of the network that sent the request
	RemoteAddr *AddrSpec
	// AddrSpec of the desired destination
	DestAddr *AddrSpec
	// AddrSpec of the actual destination (might be affected by rewrite)
	realDestAddr *AddrSpec
	bufConn      io.Reader
}

type conn interface {
	Write([]byte) (int, error)
	RemoteAddr() net.Addr
}

// NewRequest creates a new Request from the tcp connection
func NewRequest(bufConn io.Reader) (*Request, error) {
	// Read the version byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 3); err != nil {
		return nil, fmt.Errorf("Failed to get command version: %v", err)
	}

	// Ensure we are compatible
	if header[0] != socks5Version {
		return nil, fmt.Errorf("Unsupported command version: %v", header[0])
	}

	// Read in the destination address
	dest, err := readAddrSpec(bufConn)
	if err != nil {
		return nil, err
	}

	request := &Request{
		Version:  socks5Version,
		Command:  header[1],
		DestAddr: dest,
		bufConn:  bufConn,
	}

	return request, nil
}

// handleRequest is used for request processing after authentication
func (s *Server) handleRequest(req *Request, conn conn) error {
	ctx := context.Background()

	// Resolve the address if we have a FQDN
	dest := req.DestAddr
	if dest.FQDN != "" {
		ctx_, addr, err := s.config.Resolver.Resolve(ctx, dest.FQDN)
		if err != nil {
			if err := sendReply(conn, hostUnreachable, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
			return fmt.Errorf("Failed to resolve destination '%v': %v", dest.FQDN, err)
		}
		ctx = ctx_
		dest.IP = addr
	}

	// Apply any address rewrites
	req.realDestAddr = req.DestAddr
	if s.config.Rewriter != nil {
		ctx, req.realDestAddr = s.config.Rewriter.Rewrite(ctx, req)
	}

	// Switch on the command
	switch req.Command {
	case ConnectCommand:
		return s.handleConnect(ctx, conn, req)
	case BindCommand:
		return s.handleBind(ctx, conn, req)
	case AssociateCommand:
		return s.handleAssociate(ctx, conn, req)
	default:
		if err := sendReply(conn, commandNotSupported, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Unsupported command: %v", req.Command)
	}
}

// handleConnect is used to handle a connect command
func (s *Server) handleConnect(ctx context.Context, conn conn, req *Request) error {
	// Check if this is allowed
	if ctx_, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v blocked by rules", req.DestAddr)
	} else {
		ctx = ctx_
	}

	// Attempt to connect
	dial := s.config.Dial
	if dial == nil {
		dial = func(ctx context.Context, net_, addr string) (net.Conn, error) {
			return net.Dial(net_, addr)
		}
	}
	target, err := dial(ctx, "tcp", req.realDestAddr.Address())
	if err != nil {
		// Map the dial error to a SOCKS5 reply code. Matching on error
		// values keeps working when errors are wrapped or localized,
		// unlike matching on the message string.
		resp := hostUnreachable
		switch {
		case errors.Is(err, syscall.ECONNREFUSED):
			resp = connectionRefused
		case errors.Is(err, syscall.ENETUNREACH):
			resp = networkUnreachable
		}
		if err := sendReply(conn, resp, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v failed: %v", req.DestAddr, err)
	}
	defer target.Close()

	// Send success. Fall back to the unspecified address if the dialed
	// connection does not expose a *net.TCPAddr (e.g. a custom Dialer
	// returning a wrapped conn) instead of panicking on the type assertion.
	var bind AddrSpec
	if local, ok := target.LocalAddr().(*net.TCPAddr); ok {
		bind = AddrSpec{IP: local.IP, Port: local.Port}
	} else {
		bind = AddrSpec{IP: net.IPv4zero, Port: 0}
	}
	if err := sendReply(conn, successReply, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	// Start proxying
	errCh := make(chan error, 2)
	go proxy(target, req.bufConn, errCh)
	go proxy(conn, target, errCh)

	// Wait
	for range 2 {
		e := <-errCh
		if e != nil {
			// return from this function closes target (and conn).
			return e
		}
	}
	return nil
}

// handleBind is used to handle a bind command
func (s *Server) handleBind(ctx context.Context, conn conn, req *Request) error {
	// Check if this is allowed
	if ctx_, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Bind to %v blocked by rules", req.DestAddr)
	} else {
		ctx = ctx_
	}

	// TODO: Support bind
	if err := sendReply(conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	return nil
}

// handleAssociate is used to handle an associate command. It sets up a
// UDP relay per RFC 1928: datagrams from the client carry a SOCKS5 UDP
// header naming the destination, and replies are sent back with a
// header naming the source. The association lives as long as the TCP
// connection that created it.
func (s *Server) handleAssociate(ctx context.Context, conn conn, req *Request) error {
	// Check if this is allowed
	if ctx_, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Associate to %v blocked by rules", req.DestAddr)
	} else {
		ctx = ctx_
	}

	// Bind the UDP relay socket. BindIP selects the local interface when
	// set. Otherwise bind in the client's address family so the reply
	// address is dialable by the client (a v6-wildcard socket is not
	// reachable over v4 on every platform). The client port is learned
	// from the first datagram.
	network := "udp"
	if req.RemoteAddr != nil {
		if req.RemoteAddr.IP.To4() != nil {
			network = "udp4"
		} else {
			network = "udp6"
		}
	}
	bindAddr := ":0"
	if s.config.BindIP != nil {
		bindAddr = net.JoinHostPort(s.config.BindIP.String(), "0")
	}
	pc, err := net.ListenPacket(network, bindAddr)
	if err != nil {
		if err := sendReply(conn, serverFailure, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Failed to bind UDP relay socket: %v", err)
	}
	defer pc.Close()

	// Inform the client where to send its UDP datagrams
	udpLocal := pc.LocalAddr().(*net.UDPAddr)
	bind := AddrSpec{IP: udpLocal.IP, Port: udpLocal.Port}
	if err := sendReply(conn, successReply, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	s.config.Logger.Printf("[INFO] socks: UDP associate from %v relayed via %v", req.RemoteAddr, udpLocal)

	// The association lives as long as the TCP connection: closing the
	// relay socket when the client disconnects unwinds the loop below.
	go func(r io.Reader) {
		io.Copy(io.Discard, r)
		pc.Close()
	}(req.bufConn)

	// One connected UDP socket per destination, each with a relayBack
	// goroutine. Only this goroutine touches the map.
	targets := make(map[string]*net.UDPConn)
	defer func() {
		for _, tconn := range targets {
			tconn.Close()
		}
	}()

	buf := make([]byte, maxUDPDatagram)
	var clientAddr *net.UDPAddr
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			// Relay socket closed: the client disconnected (or the
			// server is shutting down).
			return nil
		}
		udpFrom, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}

		// Only datagrams from the association owner are relayed. The
		// client port is learned from the first accepted datagram (the
		// request usually carries 0.0.0.0:0); the source IP must match
		// the TCP peer when it is known, so the relay cannot be abused
		// as an open redirector.
		if clientAddr == nil {
			if req.RemoteAddr != nil && !req.RemoteAddr.IP.Equal(udpFrom.IP) {
				continue
			}
			clientAddr = udpFrom
		} else if !udpFrom.IP.Equal(clientAddr.IP) || udpFrom.Port != clientAddr.Port {
			continue
		}

		frag, dest, payload, err := unmarshalUDPHeader(buf[:n])
		if err != nil || frag != 0 {
			// Malformed or fragmented datagrams are dropped; UDP
			// fragmentation is not supported.
			continue
		}

		// Apply the rule set to the outbound destination
		outReq := &Request{
			Version:     req.Version,
			Command:     req.Command,
			AuthContext: req.AuthContext,
			RemoteAddr:  req.RemoteAddr,
			DestAddr:    dest,
		}
		if _, ok := s.config.Rules.Allow(ctx, outReq); !ok {
			continue
		}

		target := &net.UDPAddr{IP: dest.IP, Port: dest.Port}
		if dest.IP == nil {
			// FQDN destination: resolved by the system resolver (the
			// configured Resolver applies to TCP destinations).
			target, err = net.ResolveUDPAddr("udp", dest.Address())
			if err != nil {
				continue
			}
		}

		tconn := targets[target.String()]
		if tconn == nil {
			tconn, err = net.DialUDP("udp", nil, target)
			if err != nil {
				continue
			}
			targets[target.String()] = tconn
			go relayBack(pc, tconn, clientAddr)
		}
		tconn.Write(payload)
	}
}

// readAddrSpec is used to read AddrSpec.
// Expects an address type byte, followed by the address and port
func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := io.ReadFull(r, addrType); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case fqdnAddress:
		if _, err := io.ReadFull(r, addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)

	default:
		return nil, unrecognizedAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}

type closeWriter interface {
	CloseWrite() error
}

// proxy is used to shuffle data from src to destination, and sends errors
// down a dedicated channel
func proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	errCh <- err
}
