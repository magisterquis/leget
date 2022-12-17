// Program leget gets certificates from Let's Encrypt.
package main

/*
 * leget.go
 * Get certificates from Let's Encrypt
 * By J. Stuart McMurray
 * Created 20221216
 * Last Modified 20221216
 */

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const (
	// StagingURL is the URL for Let's Encrypt's staging environment.  This
	// is used instead of acme.LetsEncryptURL if -staging is given.
	StagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// StagingDir is a subdirectory in the certs directory for if we're
	// using the staging server.
	StagingDir = "staging"
)

func main() {
	var (
		staging = flag.Bool(
			"staging",
			false,
			"Use the staging server",
		)
		lAddr = flag.String(
			"listen",
			"0.0.0.0:443",
			"Listen `address`",
		)
		dir = flag.String(
			"dir",
			"leget_certs",
			"Certificate `directory`",
		)
		email = flag.String(
			"email",
			"",
			"Optional contact email `address`",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %s [options] domain [domain...]

Requests certificate(s) from Let's Encrypt for the given domain(s).  Each
domain will have its own cert and key generated.

Use of this program implies acceptance of Let's Encrypt's Terms of Service.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Make sure we have domains to request. */
	if 0 == flag.NArg() {
		log.Fatalf("No domains specified (try -h)")
	}

	/* Get a modern ClientHelloInfo.  We could use a pretty empty one, but
	then autocert would default to RSA. */
	chi, err := GetClientHelloInfo()
	if nil != err {
		log.Fatalf("Error generating template Client Hello: %s", err)
	}

	/* Work out which directory to use. */
	var dURL string
	if *staging {
		dURL = StagingURL
	}

	/* Make sure we have the certs dir. */
	*dir = filepath.Clean(*dir)
	if *staging {
		*dir = filepath.Join(*dir, StagingDir)
	}
	if err := os.MkdirAll(*dir, 0700); nil != err {
		log.Fatalf("Error making directory %s: %s", *dir, err)
	}

	/* ACME manager.  We use this to handle Let's Encrypt's connections as
	well as start the process going. */
	mgr := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(*dir),
		HostPolicy: autocert.HostWhitelist(flag.Args()...),
		Client:     &acme.Client{DirectoryURL: dURL},
		Email:      *email,
	}
	/* TLS config for handling Let's Encrypt connections. */
	conf := &tls.Config{
		GetCertificate: mgr.GetCertificate,
		NextProtos:     []string{acme.ALPNProto},
	}

	/* Handle comms from Let's Encypt. */
	l, err := net.Listen("tcp", *lAddr)
	if nil != err {
		log.Fatalf("Error listening on %s: %s", *lAddr, err)
	}
	log.Printf("Listening on %s", l.Addr())
	go func() {
		for {
			c, err := l.Accept()
			if nil != err {
				log.Fatalf(
					"Error accepting new connection: %s",
					err,
				)
			}
			go Handle(tls.Server(c, conf))
		}
	}()

	/* Request a cert for each domain we have. */
	for _, d := range flag.Args() {
		log.Printf("[%s] Requesting certificates", d)
		chi.ServerName = d
		cert, err := mgr.GetCertificate(chi)
		/* TODO: CHI with ECDSA. */
		if nil != err {
			log.Printf("[%s] Error retrieving certs: %s", d, err)
			continue
		}
		if err := SaveCert(*dir, d, cert); nil != err {
			log.Printf("[%s] Error saving certs: %s", d, err)
		}
	}

}
