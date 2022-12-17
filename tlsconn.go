package main

/*
 * tlsconn.go
 * Handle TLS connections
 * By J. Stuart McMurray
 * Created 20221216
 * Last Modified 20221216
 */

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/acme"
)

// Handle handles a TLS connection.  These should all be Let's Encrypt.
func Handle(c *tls.Conn) {
	defer c.Close()
	tag := c.RemoteAddr().String()

	/* Handshake.  This should be all we need. */
	if err := c.Handshake(); nil != err {
		log.Printf("[%s] Handshake error: %s", tag, err)
		return
	}
	cs := c.ConnectionState()
	if "" != cs.ServerName {
		tag = fmt.Sprintf("%s (%s)", c.RemoteAddr(), cs.ServerName)
	}

	/* If the handshake succeeded but we didn't agree with ALPN. */
	switch cs.NegotiatedProtocol {
	case acme.ALPNProto: /* Good */
	case "": /* No protocol negotiated. */
		log.Printf("[%s] No application protocol", tag)
		return
	default: /* Unpossible. */
		log.Printf(
			"[%s] Unexpected application protocol %q - "+
				"this is a bug",
			tag,
			cs.NegotiatedProtocol,
		)
	}
}

// GetClientHelloInfo gets a template for ClientHelloInfo.  We use this to
// avoid defaulting to RSA keys.
func GetClientHelloInfo() (*tls.ClientHelloInfo, error) {
	/* Underlying "network" connection for TLS handshake. */
	cs, cc := net.Pipe()
	defer cs.Close()
	defer cc.Close()

	/* Only here to present the ClientHelloInfo. */
	go tls.Client(cc, &tls.Config{InsecureSkipVerify: true}).Handshake()

	/* Handshake as the server.  This will fail, but we're only using it
	for its hello. */
	var (
		chi *tls.ClientHelloInfo
		hse = errors.New("handshake failed successfully")
	)
	s := tls.Server(cs, &tls.Config{GetCertificate: func(
		h *tls.ClientHelloInfo,
	) (*tls.Certificate, error) {
		chi = h
		return nil, hse
	}})
	err := s.Handshake()
	switch {
	case nil == err:
		return nil, fmt.Errorf("unexpected handshake success")
	case !errors.Is(err, hse):
		return nil, fmt.Errorf("unexpected handshake error: %w", err)
	}
	return chi, nil
}
