package socks5

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"
)

func TestSOCKS5_UDPAssociate(t *testing.T) {
	// A UDP echo server as the associate destination
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer echo.Close()
	echoAddr := echo.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, maxUDPDatagram)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			echo.WriteTo(buf[:n], from)
		}
	}()

	// SOCKS5 server
	addr := startTestServer(t, &Config{
		Logger: log.New(os.Stdout, "", log.LstdFlags),
	})

	conn := dialRetry(t, addr)
	defer conn.Close()

	// Handshake: no auth
	if _, err := conn.Write([]byte{5, 1, NoAuth}); err != nil {
		t.Fatalf("err: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("err: %v", err)
	}
	if greeting[1] != NoAuth {
		t.Fatalf("unexpected greeting reply: %v", greeting)
	}

	// ASSOCIATE request; the destination field is 0.0.0.0:0, so the
	// server learns the client address from the first datagram
	if _, err := conn.Write([]byte{5, AssociateCommand, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("err: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp[1] != successReply {
		t.Fatalf("associate failed: %v", resp)
	}

	// Where to send UDP datagrams: the relay address from the reply,
	// with unspecified addresses mapped to loopback for dialing
	relayIP := net.IP(resp[4:8])
	if relayIP.IsUnspecified() {
		relayIP = net.IPv4(127, 0, 0, 1)
	}
	relay := &net.UDPAddr{IP: relayIP, Port: int(binary.BigEndian.Uint16(resp[8:10]))}

	// The client's own UDP socket
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer client.Close()

	// Send a SOCKS-framed datagram addressed to the echo server
	dg := marshalUDPHeader(&AddrSpec{IP: echoAddr.IP, Port: echoAddr.Port}, []byte("ping"))
	if _, err := client.WriteTo(dg, relay); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Read the reply relayed back
	buf := make([]byte, maxUDPDatagram)
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	frag, src, payload, err := unmarshalUDPHeader(buf[:n])
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if frag != 0 {
		t.Fatalf("unexpected fragment: %d", frag)
	}
	if !src.IP.Equal(echoAddr.IP) || src.Port != echoAddr.Port {
		t.Fatalf("bad source in reply header: %v (want %v)", src, echoAddr)
	}
	if !bytes.Equal(payload, []byte("ping")) {
		t.Fatalf("bad payload: %q", payload)
	}

	// Closing the TCP connection tears down the association
	conn.Close()
}

func TestSOCKS5_UDPAssociate_RuleFail(t *testing.T) {
	addr := startTestServer(t, &Config{
		Rules:  PermitNone(),
		Logger: log.New(os.Stdout, "", log.LstdFlags),
	})

	conn := dialRetry(t, addr)
	defer conn.Close()

	if _, err := conn.Write([]byte{5, 1, NoAuth}); err != nil {
		t.Fatalf("err: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatalf("err: %v", err)
	}

	if _, err := conn.Write([]byte{5, AssociateCommand, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("err: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp[1] != ruleFailure {
		t.Fatalf("expected rule failure reply, got: %v", resp)
	}
}
