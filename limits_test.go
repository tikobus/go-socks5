package socks5

import (
	"errors"
	"io"
	"log"
	"net"
	"testing"
	"time"
)

// startTestServer starts a server for the given config and returns its
// listen address.
func startTestServer(t *testing.T, conf *Config) string {
	t.Helper()
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		// A closed listener is the normal teardown path, not a failure.
		if err := serv.Serve(l); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("err: %v", err)
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l.Addr().String()
}

func TestMaxConns(t *testing.T) {
	addr := startTestServer(t, &Config{
		MaxConns: 1,
		Logger:   log.New(io.Discard, "", 0),
	})

	// The first connection occupies the single slot: it never sends the
	// handshake, so its ServeConn call stays open.
	c1 := dialRetry(t, addr)
	defer c1.Close()

	// The second connection must be rejected: the server closes it
	// right away, so the read fails instead of blocking.
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the over-limit connection to be closed")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("rejection was not immediate: %v", elapsed)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	addr := startTestServer(t, &Config{
		HandshakeTimeout: 100 * time.Millisecond,
		Logger:           log.New(io.Discard, "", 0),
	})

	conn := dialRetry(t, addr)
	defer conn.Close()

	// Send nothing; the server should give up on the handshake well
	// before our read deadline.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the connection to be closed after the handshake timeout")
	}
	if elapsed := time.Since(start); elapsed >= 3*time.Second {
		t.Fatalf("handshake timeout did not fire: %v", elapsed)
	}
}

func TestIdleTimeout(t *testing.T) {
	// A target for CONNECT so the session reaches the proxying phase.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(io.Discard, c)
			}(c)
		}
	}()

	addr := startTestServer(t, &Config{
		IdleTimeout: 150 * time.Millisecond,
		Logger:      log.New(io.Discard, "", 0),
	})

	conn := dialRetry(t, addr)
	defer conn.Close()

	// Complete the handshake and a CONNECT so the session is proxied.
	port := target.Addr().(*net.TCPAddr).Port
	req := []byte{
		5, 1, NoAuth, // greeting: one method, no-auth
		5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port & 0xff), // connect
	}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Greeting reply (2 bytes) + connect reply (10 bytes).
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply := make([]byte, 12)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("err: %v", err)
	}
	if reply[1] != 0 {
		t.Fatalf("connect failed: %v", reply)
	}

	// Now go silent on both sides: the idle watchdog should close the
	// connection instead of letting it hang forever.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the idle connection to be closed")
	}
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("idle timeout did not fire: %v", elapsed)
	}
}
