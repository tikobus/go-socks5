// Command auth-server demonstrates a SOCKS5 server that requires
// username/password authentication (RFC 1929).
package main

import (
	"log"
	"os"

	socks5 "github.com/tikobus/go-socks5"
)

func main() {
	// Create a credential store mapping allowed usernames to passwords.
	// Any client that fails to present one of these pairs is rejected.
	creds := socks5.StaticCredentials{
		"alice": "secret",
		"bob":   "hunter2",
	}

	conf := &socks5.Config{
		// Providing Credentials enables user/password authentication:
		// the server offers the UserPassAuthenticator (method 0x02) and
		// falls back to no other method.
		Credentials: creds,
		Logger:      log.New(os.Stdout, "socks5: ", log.LstdFlags),
	}

	server, err := socks5.New(conf)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}

	// Serve SOCKS5 on localhost port 1080. Test with, e.g.:
	//
	//	curl --socks5 alice:secret@127.0.0.1:1080 https://example.com
	if err := server.ListenAndServe("tcp", "127.0.0.1:1080"); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
