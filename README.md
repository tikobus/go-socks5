go-socks5
=========

Provides the `socks5` package that implements a [SOCKS5 server](http://en.wikipedia.org/wiki/SOCKS).
SOCKS (Socket Secure) is used to route traffic between a client and server through
an intermediate proxy layer. This can be used to bypass firewalls or NATs.

Feature
=======

The package has the following features:
* "No Auth" mode
* User/Password authentication
* Support for the CONNECT command
* Support for the UDP ASSOCIATE command
* Rules to do granular filtering of commands
* Custom DNS resolution
* Connection limiting, handshake and idle timeouts
* Unit tests

TODO
====

The package still needs the following:
* Support for the BIND command


Example
=======

Below is a simple example of usage

```go
// Create a SOCKS5 server
conf := &socks5.Config{}
server, err := socks5.New(conf)
if err != nil {
  panic(err)
}

// Create SOCKS5 proxy on localhost port 8000
if err := server.ListenAndServe("tcp", "127.0.0.1:8000"); err != nil {
  panic(err)
}
```

A server requiring username/password authentication
([RFC 1929](https://tools.ietf.org/html/rfc1929)) can be set up by
providing a `CredentialStore`. A runnable version lives in
[examples/auth-server](examples/auth-server/main.go):

```go
// Allowed username/password pairs
creds := socks5.StaticCredentials{
  "alice": "secret",
  "bob":   "hunter2",
}

// Create a SOCKS5 server that requires user/pass authentication
conf := &socks5.Config{
  Credentials: creds,
}
server, err := socks5.New(conf)
if err != nil {
  panic(err)
}

// Create SOCKS5 proxy on localhost port 1080
if err := server.ListenAndServe("tcp", "127.0.0.1:1080"); err != nil {
  panic(err)
}
```

Clients then authenticate with `user:pass`, e.g.
`curl --socks5 alice:secret@127.0.0.1:1080 https://example.com`.
For dynamic credential sources (database, LDAP, ...), implement the
`CredentialStore` interface instead of using `StaticCredentials`:

```go
type CredentialStore interface {
  Valid(user, password string) bool
}
```

