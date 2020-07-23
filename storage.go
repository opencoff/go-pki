// storage.go - storage abstraction
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package pki

import (
	"math/big"
	"time"
)

// Storage abstracts the underlying persistent storage provider.
type Storage interface {
	Rekey(newpw string) error
	Close() error

	// Get the Root CA
	GetRootCA() (*Cert, error)

	// Store root CA
	StoreRootCA(*Cert) error

	// Return current serial#
	GetSerial() *big.Int

	// increment serial#, update db and return new serial#
	NewSerial() (*big.Int, error)

	// get intermediate CA
	GetICA(nm string) (*Cert, error)

	// Fetch client cert
	GetClientCert(nm string, pw string) (*Cert, error)

	// Fetch server cert
	GetServerCert(nm string, pw string) (*Cert, error)

	// Store intermediate CA
	StoreICA(c *Cert) error

	// Store client cert
	StoreClientCert(c *Cert, pw string) error

	// Store server cert
	StoreServerCert(c *Cert, pw string) error

	// Delete a given CA -- revocation
	DeleteICA(cn string) error

	// Delete client cert
	DeleteClientCert(cn string) error

	// delete server cert
	DeleteServerCert(cn string) error

	// - Iterators -
	MapICA(func(*Cert) error) error
	MapClientCerts(func(*Cert) error) error
	MapServerCerts(func(*Cert) error) error
	MapRevoked(func(time.Time, *Cert)) error


	FindRevoked(skid []byte) (time.Time, *Cert, error)
}

// vim: ft=go:noexpandtab:sw=8:ts=8
