package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"
)

// dialRetry dials addr, retrying briefly until the server is accepting
// connections, so tests do not depend on sleeps for synchronization.
func dialRetry(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("failed to dial %s: %v", addr, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestNew_DoesNotMutateConfig(t *testing.T) {
	conf := &Config{}
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// The caller's Config must be left untouched...
	if conf.AuthMethods != nil {
		t.Fatal("caller Config.AuthMethods was mutated")
	}
	if conf.Resolver != nil {
		t.Fatal("caller Config.Resolver was mutated")
	}
	if conf.Rules != nil {
		t.Fatal("caller Config.Rules was mutated")
	}
	if conf.Logger != nil {
		t.Fatal("caller Config.Logger was mutated")
	}

	// ...while the server must still work from its internal defaults.
	if len(serv.config.AuthMethods) == 0 {
		t.Fatal("server has no auth methods")
	}
	if serv.config.Rules == nil {
		t.Fatal("server has no ruleset")
	}
}

func TestSOCKS5_Connect(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Errorf("err: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Errorf("err: %v", err)
			return
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Errorf("bad: %v", buf)
			return
		}
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Create a socks server
	creds := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: creds}
	conf := &Config{
		AuthMethods: []Authenticator{cator},
		Logger:      log.New(os.Stdout, "", log.LstdFlags),
	}
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Start listening on an ephemeral port
	socksL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() { socksL.Close() })
	go func() {
		// A closed listener is the normal teardown path, not a failure.
		if err := serv.Serve(socksL); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("err: %v", err)
		}
	}()

	// Get a local conn, retrying until the server is accepting
	conn := dialRetry(t, socksL.Addr().String())

	// Connect, auth and connect to local
	req := bytes.NewBuffer(nil)
	req.Write([]byte{5})
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	req.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	req.Write(port)

	// Send a ping
	req.Write([]byte("ping"))

	// Send all the bytes
	conn.Write(req.Bytes())

	// Verify response
	expected := []byte{
		socks5Version, UserPassAuth,
		1, authSuccess,
		5,
		0,
		0,
		1,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}
	out := make([]byte, len(expected))

	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadAtLeast(conn, out, len(out)); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Ignore the port
	out[12] = 0
	out[13] = 0

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v", out)
	}
}
