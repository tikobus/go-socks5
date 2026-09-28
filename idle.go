package socks5

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// activityConn wraps a net.Conn and records the time of the last read
// or write. newIdleWatch additionally runs a watchdog goroutine that
// closes the underlying connection once it has been idle (no reads or
// writes) for the configured duration, which unwinds any goroutines
// blocked on it.
type activityConn struct {
	net.Conn
	lastActivity atomic.Int64 // unix nanos
	stopCh       chan struct{}
	stopOnce     sync.Once
}

// newIdleWatch wraps c so that it is closed after being idle for the
// given duration.
func newIdleWatch(c net.Conn, idle time.Duration, logger *log.Logger) *activityConn {
	ac := &activityConn{
		Conn:   c,
		stopCh: make(chan struct{}),
	}
	ac.lastActivity.Store(time.Now().UnixNano())

	go func() {
		// Check at half the idle period so the effective close time is
		// within [idle, 1.5*idle) of the last activity.
		ticker := time.NewTicker(idle / 2)
		defer ticker.Stop()
		for {
			select {
			case <-ac.stopCh:
				return
			case <-ticker.C:
				last := time.Unix(0, ac.lastActivity.Load())
				if time.Since(last) >= idle {
					logger.Printf("[WARN] socks: Closing idle connection from %v", ac.RemoteAddr())
					ac.Conn.Close()
					return
				}
			}
		}
	}()

	return ac
}

// stop terminates the watchdog goroutine; it is safe to call more than
// once and after the connection is closed.
func (a *activityConn) stop() {
	a.stopOnce.Do(func() { close(a.stopCh) })
}

func (a *activityConn) Read(b []byte) (int, error) {
	n, err := a.Conn.Read(b)
	if n > 0 {
		a.lastActivity.Store(time.Now().UnixNano())
	}
	return n, err
}

func (a *activityConn) Write(b []byte) (int, error) {
	n, err := a.Conn.Write(b)
	if n > 0 {
		a.lastActivity.Store(time.Now().UnixNano())
	}
	return n, err
}
