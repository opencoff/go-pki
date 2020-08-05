[![GoDoc](https://godoc.org/github.com/opencoff/go-pki?status.svg)](https://godoc.org/github.com/opencoff/go-pki)

## TL;DR
This is an opinionated single-file OpenVPN TLS certificate library.
It has _no_ dependencies on any other external tool such as openssl.

## Features
* Uses a single [boltdb](https://github.com/etcd/bbolt) instance to store the
  certificates and keys.
* All data strored in the database is encrypted with keys derived from a user
  supplied CA passphrase.
* Support for issuing & revoking:
   - Server Certs (optionally signed by intermediate CAs)
   - Client Certs (optionally signed by intermediate CAs)
   - Intermediate CA certs (optionally signed by other intermediate
     CAs)
* Flexible CRL generation
* The certificates and keys are opinionated:
   * All CA cert private keys are Secp521r1
   * Client & Servers cert private keys are Secp256k1
   * "SSL-Server" attribute set on server certificates (nsCertType)
   * "SSL-Client" attribute set on client certificates (nsCertType)
   * ECDSA with SHA512 is used as the signature algorithm
     of encryption to thwart DoS attacks.


## Who uses this?
Two tools use this:

* [ovpn-tool](https://github.com/opencoff/ovpn-tool) - an opnionated
  PKI and OpenVPN Configuration manager
* [certik](https://github.com/opencoff/certik) - an example CLI
  program that uses this library


## How to use this?
You will need a fairly recent golang toolchain (>1.10). `go-pki` is
modules ready. You just import the code in your project as:

```go

    import (
        "github.com/opencoff/go-pki"
    )

```


