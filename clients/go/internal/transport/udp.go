package transport

import (
	"fmt"
	"net"
)

// UDPTransport is a connected UDP datagram socket (cleartext).
type UDPTransport struct {
	host string
	port int
	conn *net.UDPConn
}

// NewUDP dials a UDP socket connected to host:port.
func NewUDP(host string, port int) (*UDPTransport, error) {
	t := &UDPTransport{host: host, port: port}
	if err := t.open(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *UDPTransport) open() error {
	conn, err := dialUDP(t.host, t.port)
	if err != nil {
		return err
	}
	t.conn = conn
	return nil
}

func dialUDP(host string, port int) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	if err := setNonblock(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (t *UDPTransport) Send(buf []byte) (int, error) {
	return t.conn.Write(buf)
}

func (t *UDPTransport) Reconnect() error {
	conn, err := dialUDP(t.host, t.port)
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

func (t *UDPTransport) Close() error {
	if t.conn == nil {
		return nil
	}
	err := t.conn.Close()
	t.conn = nil
	return err
}
