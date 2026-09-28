package socks5

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

const (
	socks5Version = uint8(5)
)

// Config is used to setup and configure a Server
type Config struct {
	// AuthMethods can be provided to implement custom authentication
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	AuthMethods []Authenticator

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AuthMethods is nil, then "auth-less" mode is enabled.
	Credentials CredentialStore

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	Rules RuleSet

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter AddressRewriter

	// BindIP is used for bind or udp associate
	BindIP net.IP

	// Logger can be used to provide a custom log target.
	// Defaults to stdout.
	Logger *log.Logger

	// MaxConns limits the number of concurrently served client
	// connections. When the limit is reached, new connections are
	// rejected. Zero (the default) means no limit.
	MaxConns int

	// HandshakeTimeout bounds the time allowed for the version,
	// authentication, and request phase of each connection. Zero (the
	// default) means no limit.
	HandshakeTimeout time.Duration

	// IdleTimeout closes client connections that have seen no reads or
	// writes for this long, including established proxy sessions. Zero
	// (the default) means no limit.
	IdleTimeout time.Duration

	// Optional function for dialing out
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config *Config
	// sem bounds the number of concurrently served connections when
	// Config.MaxConns is set; nil means unbounded.
	sem chan struct{}
}

// New creates a new Server and potentially returns an error
func New(conf *Config) (*Server, error) {
	// Work on a copy so the caller's Config is never mutated: sharing a
	// single Config across servers (or reading it after New) would race.
	cfg := *conf

	// Ensure we have at least one authentication method enabled
	if len(cfg.AuthMethods) == 0 {
		if cfg.Credentials != nil {
			cfg.AuthMethods = []Authenticator{&UserPassAuthenticator{cfg.Credentials}}
		} else {
			cfg.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	// Ensure we have a DNS resolver
	if cfg.Resolver == nil {
		cfg.Resolver = DNSResolver{}
	}

	// Ensure we have a rule set
	if cfg.Rules == nil {
		cfg.Rules = PermitAll()
	}

	// Ensure we have a log target
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	// The error return exists for API compatibility; constructing a
	// server cannot fail.
	server := &Server{config: &cfg}
	if cfg.MaxConns > 0 {
		server.sem = make(chan struct{}, cfg.MaxConns)
	}
	return server, nil
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			// A closed listener means we are done; any other failure
			// (e.g. EMFILE, ECONNABORTED) is treated as transient:
			// back off briefly and retry instead of taking the
			// server down.
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			s.config.Logger.Printf("[ERR] socks: Accept failure: %v", err)
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if s.sem != nil {
			select {
			case s.sem <- struct{}{}:
			default:
				s.config.Logger.Printf("[WARN] socks: Rejecting connection from %v: max connections reached", conn.RemoteAddr())
				conn.Close()
				continue
			}
		}
		go func() {
			defer func() {
				if s.sem != nil {
					<-s.sem
				}
			}()
			s.ServeConn(conn)
		}()
	}
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(conn net.Conn) error {
	defer conn.Close()

	// Bound the negotiation phase so half-open clients cannot hold
	// resources open indefinitely.
	if s.config.HandshakeTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(s.config.HandshakeTimeout))
	}

	// Track activity and enforce the idle timeout across the whole
	// connection lifetime, including established proxy sessions.
	if s.config.IdleTimeout > 0 {
		watch := newIdleWatch(conn, s.config.IdleTimeout, s.config.Logger)
		defer watch.stop()
		conn = watch
	}

	bufConn := bufio.NewReader(conn)

	// Read the version byte
	version := []byte{0}
	if _, err := io.ReadFull(bufConn, version); err != nil {
		s.config.Logger.Printf("[ERR] socks: Failed to get version byte: %v", err)
		return err
	}

	// Ensure we are compatible
	if version[0] != socks5Version {
		err := fmt.Errorf("Unsupported SOCKS version: %v", version)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	// Authenticate the connection
	authContext, err := s.authenticate(conn, bufConn)
	if err != nil {
		err = fmt.Errorf("Failed to authenticate: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	request, err := NewRequest(bufConn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("Failed to read destination address: %v", err)
	}

	// Negotiation is done; drop the handshake deadline so long-lived
	// sessions are not bound by it.
	if s.config.HandshakeTimeout > 0 {
		conn.SetReadDeadline(time.Time{})
	}

	request.AuthContext = authContext
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}

	// Process the client request
	if err := s.handleRequest(request, conn); err != nil {
		err = fmt.Errorf("Failed to handle request: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	return nil
}
