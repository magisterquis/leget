package main

/*
 * get.go
 * Trigger getting a certificate
 * By J. Stuart McMurray
 * Created 20221216
 * Last Modified 20221217
 */

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// SaveCert saves the domain name's certificate, its key, and its issuer cert
// to dir.
func SaveCert(dir, name string, cert *tls.Certificate) error {
	/* Save off the key. */
	if err := saveKey(dir, name, cert.PrivateKey); nil != err {
		return fmt.Errorf("saving private key: %w", err)
	}
	/* Save off the leaf cert. */
	if err := saveCerts(
		dir,
		name,
		"certificate",
		".crt",
		[][]byte{cert.Certificate[0]},
	); nil != err {
		return fmt.Errorf("saving leaf certificate: %w", err)
	}
	/* Save off the rest of the chain. */
	if err := saveCerts(
		dir,
		name,
		"issuer certificate chain",
		".issuer.crt",
		cert.Certificate[1:],
	); nil != err {
		return fmt.Errorf("saving issuer chain: %w", err)
	}

	return nil
}

// saveKey saves the private key k.
func saveKey(dir, name string, key crypto.PrivateKey) error {
	fn := filepath.Join(dir, name+".key")

	/* DER-encode. */
	var (
		Type  string
		Bytes []byte
	)
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		Type = "EC"
		var err error
		Bytes, err = x509.MarshalECPrivateKey(k)
		if nil != err {
			return fmt.Errorf("DER-encoding: %w", err)
		}
	case *rsa.PrivateKey:
		Type = "RSA"
		Bytes = x509.MarshalPKCS1PrivateKey(k)
	default:
		return fmt.Errorf("unknown private key type %T", key)
	}
	/* PEM-encode to a file. */
	f, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if nil != err {
		return fmt.Errorf("opening file %q: %w", fn, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{
		Type:  Type,
		Bytes: Bytes,
	}); nil != err {
		return fmt.Errorf("writing to file: %w", err)
	}

	log.Printf("[%s] Wrote key to %s", name, f.Name())
	return nil
}

// saveCerts saves the certificates to a PEM file with the given suffix.
func saveCerts(
	dir string,
	name string,
	what string,
	suffix string,
	certs [][]byte,
) error {
	fn := filepath.Join(dir, name+suffix)

	/* File to which to save certs. */
	f, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if nil != err {
		return fmt.Errorf("opening file %q: %w", fn, err)
	}
	defer f.Close()

	/* Write ALL the certs. */
	for _, cert := range certs {
		if err := pem.Encode(f, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		}); nil != err {
			return fmt.Errorf("writing certificate: %w", err)
		}
	}

	log.Printf("[%s] Wrote %s to %s", name, what, f.Name())
	return nil
}
