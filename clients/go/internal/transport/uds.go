package transport

import (
	"net"
	"syscall"
)

// UDSTransport is a connected Unix-domain datagram socket. The default
// transport for varta.Connect.
type UDSTransport struct {
	path string
	conn *net.UnixConn
}

// NewUDS dials a unixgram socket connected to path. The returned
// transport is non-blocking; WouldBlock surfaces as a syscall error
// for the agent layer to classify.
func NewUDS(path string) (*UDSTransport, error) {
	t := &UDSTransport{path: path}
	if err := t.open(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *UDSTransport) open() error {
	conn, err := dialUDS(t.path)
	if err != nil {
		return err
	}
	t.conn = conn
	return nil
}

func dialUDS(path string) (*net.UnixConn, error) {
	addr, err := net.ResolveUnixAddr("unixgram", path)
	if err != nil {
		return nil, err
	}
	// DialUnix on "unixgram" returns a connected datagram socket.
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return nil, err
	}
	if err := setNonblock(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// Send transmits buf. Returns the underlying *net.OpError verbatim so
// errnoclass can recover the wrapped syscall.Errno.
func (t *UDSTransport) Send(buf []byte) (int, error) {
	return t.conn.Write(buf)
}

// Reconnect prepares a replacement before retiring the active socket.
func (t *UDSTransport) Reconnect() error {
	conn, err := dialUDS(t.path)
	if err != nil {
		return err
	}
	old := t.conn
	t.conn = conn
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (t *UDSTransport) Close() error {
	if t.conn == nil {
		return nil
	}
	err := t.conn.Close()
	t.conn = nil
	return err
}

// setNonblock toggles O_NONBLOCK on the underlying file descriptor.
// net.DialUnix returns a blocking socket on most platforms; the Varta
// contract is non-blocking I/O.
func setNonblock(conn interface {
	SyscallConn() (syscall.RawConn, error)
}) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	err = raw.Control(func(fd uintptr) {
		inner = syscall.SetNonblock(int(fd), true)
	})
	if err != nil {
		return err
	}
	return inner
}
