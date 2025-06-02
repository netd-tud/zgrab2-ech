package ech

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
)

func toStrSlice[T fmt.Stringer](inputs []T) []string {
	out := make([]string, len(inputs))

	for i, value := range inputs {
		out[i] = value.String()
	}

	return out
}

func hexFromByteErr(fn func() ([]byte, error)) string {
	b, err := fn()
	if err != nil {
		b = nil
	}
	return hex.EncodeToString(b)
}

func toPtr[T any](value T) *T {
	return &value
}

func toIntSlice[T ~[]byte](vs T) []int {
	if vs == nil || len(vs) == 0 {
		return nil
	}

	ints := make([]int, len(vs))

	for i, v := range vs {
		ints[i] = int(v)
	}

	return ints
}

func ipFromTlsConn(conn *tls.Conn) *string {
	if conn == nil || conn.NetConn() == nil {
		return nil
	}

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil
	}
	return &host
}

func transportFromTlsConn(conn *tls.Conn) *string {
	if conn == nil || conn.NetConn() == nil {
		return nil
	}

	transport := conn.RemoteAddr().Network()
	return &transport
}

func versionFromTlsConn(conn *tls.Conn) *string {
	if conn == nil {
		return nil
	}

	version := tls.VersionName(conn.ConnectionState().Version)
	return &version
}

func echAcceptedFromTlsConn(conn *tls.Conn) *bool {
	if conn == nil {
		return nil
	}

	accepted := conn.ConnectionState().ECHAccepted
	return &accepted
}

func handshakeCompletedFromTlsConn(conn *tls.Conn) *bool {
	if conn == nil {
		return nil
	}

	complete := conn.ConnectionState().HandshakeComplete

	return &complete
}

func protoFromTlsConn(conn *tls.Conn) *string {
	if conn == nil {
		return nil
	}

	proto := conn.ConnectionState().NegotiatedProtocol

	return &proto
}

func cipherFromTlsConn(conn *tls.Conn) *string {
	if conn == nil {
		return nil
	}

	proto := tls.CipherSuiteName(conn.ConnectionState().CipherSuite)

	return &proto
}

func clientHelloOuterFromTlsConn(conn *tls.Conn) tls.ClientHelloMsg {
	if conn == nil {
		return tls.ClientHelloMsg{}
	}

	return conn.ClientHelloOuter
}

func clientHelloInnerFromTlsConn(conn *tls.Conn) tls.ClientHelloMsg {
	if conn == nil && conn.ClientHelloInner == nil {
		return tls.ClientHelloMsg{}
	}

	return *conn.ClientHelloInner
}

func serverHelloFromTlsConn(conn *tls.Conn) tls.ServerHelloMsg {
	if conn == nil {
		return tls.ServerHelloMsg{}
	}

	return conn.ServerHello
}
