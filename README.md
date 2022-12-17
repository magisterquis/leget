LE Get
======
Simple ACME client to grab TLS certs from
[Let's Encrypt](http://letsencrypt.org).  Really, it's just a wrapper around
Go's [autocert](golang.org/x/crypto/acme/autocert) library.

Features
--------
- Generates private keys and requests certs from Let's Encrypt
- Handles tls-alpn-01
- Simple interface

Quickstart
----------
```sh
$ go install github.com/magisterquis/leget@latest
$ leget example.com example.org
2022/12/17 16:43:32 Listening on 0.0.0.0:443
2022/12/17 16:43:32 [example.com] Requesting certificates
2022/12/17 16:43:32 [example.com] Wrote key to leget_certs/example.com.key
2022/12/17 16:43:32 [example.com] Wrote certificate to leget_certs/example.com.crt
2022/12/17 16:43:32 [example.com] Wrote issuer certificate chain to leget_certs/example.com.issuer.crt
2022/12/17 16:43:32 [example.org] Requesting certificates
2022/12/17 16:43:32 [example.org] Wrote key to leget_certs/example.org.key
2022/12/17 16:43:32 [example.org] Wrote certificate to leget_certs/example.org.crt
2022/12/17 16:43:32 [example.org] Wrote issuer certificate chain to leget_certs/example.org.issuer.crt
$ ls leget_certs/
acme_account+key           example.com.issuer.crt     example.org.crt
example.com                example.com.key            example.org.issuer.crt
example.com.crt            example.org                example.org.key
```

Usage
-----
```
Usage: leget [options] domain [domain...]

Requests certificate(s) from Let's Encrypt for the given domain(s).  Each
domain will have its own cert and key generated.

Use of this program implies acceptance of Let's Encrypt's Terms of Service.

Options:
  -dir directory
    	Certificate directory (default "leget_certs")
  -email address
    	Optional contact email address
  -listen address
    	Listen address (default "0.0.0.0:443")
  -staging
    	Use the staging server
```
