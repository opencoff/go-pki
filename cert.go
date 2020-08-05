// cert.go - opinionated pki manager
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

// Package pki abstracts creating an opinionated PKI.
// The certs and keys are stored in a boltDB instance. The private keys
// are stored in encrypted form. The CA passphrase is used in a KDF to derive
// the encryption keys. User (client) certs are also encrypted - but with
// user provided passphrase.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"runtime"
	"time"
)

// Minimum validity of any signing CA: 1 day
const _MinValidity time.Duration = 24 * time.Hour

// CA is a special type of Credential that also has a CSR in it.
type CA struct {
	*x509.Certificate

	Expired   bool
	CARevoked bool

	key *ecdsa.PrivateKey

	parent *CA

	// persistent storage
	db Storage

	// clock for timekeeping; used for tests
	clock clock
}

// time keeper - should return the current time in UTC
type clock interface {
	Now() time.Time
}

// Cert represents a client or server certificate
type Cert struct {
	*x509.Certificate

	Key    *ecdsa.PrivateKey
	Rawkey []byte

	IsServer  bool
	IsCA      bool
	Expired   bool
	CARevoked bool

	// Additional info provided when cert was created
	Additional []byte
}

// Information needed to create a certificate
type CertInfo struct {
	Subject  pkix.Name
	Validity time.Duration

	EmailAddresses []string
	DNSNames       []string

	// We only support exactly _one_ IP address
	IPAddresses []net.IP

	// Additional info stored in the DB against this certificate
	// This info is *NOT* in the x509 object.
	Additional []byte
}

// Revoked Certificate
type Revoked struct {
	*Cert
	When time.Time
}

// Config holds the initial info needed to setup a CA
type Config struct {
	// Passphrase to encrypt the CA credentials
	Passwd string

	// Root-CA subject name; also used for all intermediate CAs
	Subject pkix.Name

	// Validity of the root-CA
	Validity time.Duration
}

// New creates a new PKI CA instance with storage backed by boltdb in 'dbname'
func New(cfg *Config, dbname string, create bool) (*CA, error) {
	clk := newSysClock()
	dbc := &dbConfig{
		Name:   dbname,
		Passwd: cfg.Passwd,
		Create: create,
	}
	db, err := openBoltDB(dbc, clk)
	if err != nil {
		return nil, err
	}
	return newWithClock(cfg, clk, db, create)
}

// NewFromJSON creates a new PKI CA instance with storage backed by boltDB in 'dbname'
// with initial contents coming from the JSON blob
func NewFromJSON(cfg *Config, dbname, jsonStr string) (*CA, error) {
	clk := newSysClock()
	dbc := &dbConfig{
		Name:   dbname,
		Passwd: cfg.Passwd,
		Json:   jsonStr,
		Create: true,
	}
	db, err := openBoltDB(dbc, clk)
	if err != nil {
		return nil, err
	}
	return newWithClock(cfg, clk, db, true)
}

// NewWithStorage creates a new RootCA with the given storage engine
func NewWithStorage(cfg *Config, db Storage, create bool) (*CA, error) {
	clk := newSysClock()
	return newWithClock(cfg, clk, db, create)
}

// internal function to create new CA with the given time keeper
func newWithClock(cfg *Config, clk clock, db Storage, create bool) (*CA, error) {
	ck, err := db.GetRootCA()
	if err != nil {
		return nil, err
	}

	// so we don't have a root CA. We create one if it was asked
	if ck == nil {
		if !create {
			return nil, fmt.Errorf("CA not initialized and create-if-missing not set")
		}

		if len(cfg.Subject.CommonName) == 0 {
			return nil, fmt.Errorf("CA Common Name can't be empty")
		}

		now := clk.Now()
		exp := now.Add(cfg.Validity)
		if exp.Before(now) {
			return nil, fmt.Errorf("CA Validity is in the past!")
		}

		ck, err = createRootCA(cfg, clk, db)
		if err != nil {
			return nil, err
		}
	} else {
		now := clk.Now()
		if ck.NotAfter.Sub(now) <= _MinValidity {
			return nil, ErrExpired
		}
	}

	ca := &CA{
		Certificate: ck.Certificate,
		key:         ck.Key,
		db:          db,
		clock:       clk,
	}
	// root-ca are born of themselves
	ca.parent = ca
	return ca, nil
}

// Close the CA and associated storage
func (ca *CA) Close() error {
	ca.key = nil

	// break the circular ref for the GC to pick this up sooner
	for ; ca != ca.parent; ca = ca.parent {
	}
	ca.parent = nil
	return ca.db.Close()
}

// Change the DB encryption key. This merely changes the KEK for the DB.
func (ca *CA) Rekey(newpw string) error {
	return ca.db.Rekey(newpw)
}

// NewClientCert issues a new client certificate
func (ca *CA) NewClientCert(ci *CertInfo, pw string) (*Cert, error) {
	return ca.newCert(ci, pw, false)
}

// NewServerCert issues a new server certificate
func (ca *CA) NewServerCert(ci *CertInfo, pw string) (*Cert, error) {
	return ca.newCert(ci, pw, true)
}

// Sign the given CSR with the provided CA
func (ca *CA) SignCert(csr *x509.Certificate) (*x509.Certificate, error) {
	if csr.IsCA {
		return nil, fmt.Errorf("sign: can't add new intermediate CA without key")
	}

	var isServer bool = true
	for i := range csr.ExtKeyUsage {
		ku := csr.ExtKeyUsage[i]
		if ku == x509.ExtKeyUsageClientAuth {
			isServer = false
			break
		}
	}

	if len(csr.SubjectKeyId) == 0 {
		mb, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("can't marshal CSR Public Key: %w", err)
		}
		csr.SubjectKeyId = hash(mb)
	}

	serial, err := ca.db.NewSerial()
	if err != nil {
		return nil, err
	}

	csr.SerialNumber = serial
	csr.BasicConstraintsValid = true
	csr.MaxPathLenZero = true
	csr.MaxPathLen = -1

	der, err := x509.CreateCertificate(rand.Reader, csr, ca.Certificate, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("%s: can't sign cert: %w", csr.Subject.CommonName, err)
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	ck := &Cert{
		Certificate: crt,
		Key:         nil,
	}

	if isServer {
		err = ca.db.StoreServerCert(ck, "")
	} else {
		err = ca.db.StoreClientCert(ck, "")
	}

	if err != nil {
		return nil, err
	}

	return crt, nil
}

// RevokeCA revokes a given intermediate CA
// We don't allow for the root-ca to be revoked.
func (ca *CA) RevokeCA(cn string) error {
	return ca.db.DeleteICA(cn)
}

// RevokeServer revokes the given server
func (ca *CA) RevokeServer(cn string) error {
	return ca.db.DeleteServerCert(cn)
}

// RevokeClient revokes the given client
func (ca *CA) RevokeClient(cn string) error {
	return ca.db.DeleteClientCert(cn)
}

// Return true if 'xca' is revoked. This looks in the global namespace and not
// just the CAs signed by 'ca'.
func (ca *CA) IsRevokedCA(xca *CA) (bool, error) {
	rv, err := ca.ListRevoked()
	if err != nil {
		return false, err
	}

	key := fmt.Sprintf("%x", xca.SubjectKeyId)
	_, ok := rv[key]
	if ok {
		return true, nil
	}
	return false, nil
}

// Export Entire DB as a JSON
func (ca *CA) ExportJSON(wr io.Writer) error {
	js, err := ca.db.ExportJSON()
	if err != nil {
		return err
	}

	_, err = wr.Write([]byte(js))
	return err
}

// Find _all_ entities in the system: client certs, server certs and intermediate certs
func (ca *CA) Find(cn string) (*Cert, error) {
	fps := []func(cn string) (*Cert, error){
		ca.db.GetICA,
		func(cn string) (*Cert, error) { return ca.db.GetServerCert(cn, "") },
		func(cn string) (*Cert, error) { return ca.db.GetClientCert(cn, "") },
	}
	for i := range fps {
		ck, err := fps[i](cn)

		switch {
		case err == nil:
			if ok, err := ca.isRevokedCA(ck.AuthorityKeyId); err == nil && ok {
				return ck, ErrCARevoked
			}
			return ca.validate(ck)
		case err != ErrNotFound:
			return nil, err
		}
	}

	return nil, ErrNotFound
}

// Find the CA with the given name. This operates on the global "namespace".
// i.e., even if 'ca' is an intermediate CA, it will search in the parent
// namespaces till a match is found.
func (ca *CA) FindCA(cn string) (*CA, error) {
	ck, err := ca.db.GetICA(cn)
	if err != nil {
		return nil, err
	}

	if ck, err = ca.validate(ck); err != nil {
		return nil, err
	}

	m, rca, err := ca.findCAs()
	if err != nil {
		return nil, err
	}

	skid := fmt.Sprintf("%x", ck.SubjectKeyId)
	ica, ok := m[skid]
	if !ok {
		return nil, ErrCARevoked
	}

	// our parents should still be valid
	if isRevoked(m, rca, ck.AuthorityKeyId) {
		return nil, ErrCARevoked
	}

	return ica, nil
}

// We don't need to check for revocation in any of the Findx() functions;
// If a CN is found in the DB, then it hasn't yet been revoked. We only need
// to verify its expiry state (done via ca.validate())

// FindClient returns the given client cert
func (ca *CA) FindClient(cn string) (*Cert, error) {
	ck, err := ca.db.GetClientCert(cn, "")
	if err == nil {
		if ok, err := ca.isRevokedCA(ck.AuthorityKeyId); err == nil && ok {
			ck.CARevoked = true
			return ck, ErrCARevoked
		}
		ck, err = ca.validate(ck)
	}

	return ck, err
}

// FindServer returns the given server cert
func (ca *CA) FindServer(cn string) (*Cert, error) {
	ck, err := ca.db.GetServerCert(cn, "")
	if err == nil {
		if ok, err := ca.isRevokedCA(ck.AuthorityKeyId); err == nil && ok {
			ck.CARevoked = true
			return ck, ErrCARevoked
		}
		ck, err = ca.validate(ck)
	}
	return ck, err
}

// Return all server certs
func (ca *CA) GetServers() ([]*Cert, error) {
	m, rca, err := ca.findCAs()
	if err != nil {
		return nil, err
	}

	z := make([]*Cert, 0, 4)
	err = ca.db.MapServerCerts(func(c *Cert) error {
		if isRevoked(m, rca, c.AuthorityKeyId) {
			c.CARevoked = true
		}
		c, _ = ca.validate(c)
		z = append(z, c)
		return nil
	})

	if err != nil {
		return nil, err
	}
	return z, nil
}

// Return all the client certs
func (ca *CA) GetClients() ([]*Cert, error) {
	m, rca, err := ca.findCAs()
	if err != nil {
		return nil, err
	}

	z := make([]*Cert, 0, 4)
	err = ca.db.MapClientCerts(func(c *Cert) error {
		if isRevoked(m, rca, c.AuthorityKeyId) {
			c.CARevoked = true
		}
		c, _ = ca.validate(c)
		z = append(z, c)
		return nil
	})

	if err != nil {
		return nil, err
	}
	return z, nil
}

// Return _all_ CAs in the system (including the root CA)
func (ca *CA) GetCAs() ([]*CA, error) {
	m, _, err := ca.findCAs()
	if err != nil {
		return nil, err
	}

	// convert the map into a list
	z := make([]*CA, 0, len(m))
	for _, s := range m {
		z = append(z, s)
	}
	return z, nil
}

// return the signing chain for _this_ CA
func (ca *CA) Chain() ([]*CA, error) {
	ck := &Cert{
		Certificate: ca.Certificate,
		Key:         ca.key,
		IsCA:        true,
	}
	return ca.ChainFor(ck)
}

// Return chain of signing certs for the named cert. This function operates
// on the global namespace; i.e., it is NOT dependent on the specific instance
// of 'ca' (which may be an intermediate CA).
func (ca *CA) ChainFor(c *Cert) ([]*CA, error) {
	m, rca, err := ca.findCAs()
	if err != nil {
		return nil, err
	}

	// walk the CAs and build the signing chain
	z := make([]*CA, 0, 4)
	if c.IsCA {
		skid := fmt.Sprintf("%x", c.SubjectKeyId)
		s, ok := m[skid]
		if !ok {
			return nil, fmt.Errorf("can't find issuer for %s", skid)
		}
		z = append(z, s)
	}

	akid := fmt.Sprintf("%x", c.AuthorityKeyId)
	rkid := fmt.Sprintf("%x", rca.SubjectKeyId)
	for {
		s, ok := m[akid]
		if !ok {
			return nil, fmt.Errorf("can't find issuer %x", akid)
		}
		z = append(z, s)
		if akid == rkid {
			break
		}

		// Next iteration: walk up the chain
		akid = fmt.Sprintf("%x", s.AuthorityKeyId)
	}
	return z, nil
}

// Return list of revoked certs
func (ca *CA) GetAllRevoked() (*pkix.CertificateList, error) {
	// fetch with a one day validity
	der, err := ca.crl(1)
	if err != nil {
		return nil, err
	}

	cl, err := x509.ParseDERCRL(der)
	if err != nil {
		return nil, err
	}

	return cl, nil
}

// Return a CRL with a given validity
func (ca *CA) CRL(crlValidDays int) ([]byte, error) {
	der, err := ca.crl(crlValidDays)
	if err != nil {
		return nil, err
	}
	p := pem.Block{
		Type:  "X509 CRL",
		Bytes: der,
	}
	return pem.EncodeToMemory(&p), nil
}

func (ca *CA) ListRevoked() (map[string]Revoked, error) {
	m := make(map[string]Revoked)
	err := ca.db.MapRevoked(func(t time.Time, c *Cert) {
		key := fmt.Sprintf("%x", c.SubjectKeyId)
		m[key] = Revoked{
			Cert: c,
			When: t,
		}
	})

	return m, err
}

// Create and issue a new intermediate CA cert
func (ca *CA) NewIntermediateCA(ci *CertInfo) (*CA, error) {
	if !ca.IsValid() {
		return nil, ErrExpired
	}

	eckey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("inter-ca: can't generate ECC P256 key: %s", err)
	}

	serial, err := ca.db.NewSerial()
	if err != nil {
		return nil, fmt.Errorf("can't generate new serial#: %w", err)
	}

	cn := ci.Subject.CommonName
	pubkey := eckey.Public().(*ecdsa.PublicKey)
	now := ca.clock.Now()
	template := x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA512,
		PublicKeyAlgorithm: x509.ECDSA,
		SerialNumber:       serial,
		Issuer:             ca.Subject,
		Subject:            ci.Subject,
		NotBefore:          now,
		NotAfter:           now.Add(ci.Validity),

		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            -1,
		SubjectKeyId:          cksum(pubkey),
		AuthorityKeyId:        ca.SubjectKeyId,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	/**
	 * We created the root CA with a path-length-constraint = false (PathLen == -1).
	 * So, we can safely skip this step.
	 *
	 * If we ever support MaxPathLen in the Config struct, the two lines below
	 * account for proper path-len constraint.
	 */
	if ca.MaxPathLen > 0 {
		template.MaxPathLen = ca.MaxPathLen - 1
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, ca.Certificate, pubkey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("%s: can't sign intermediate CA cert: %w", cn, err)
	}

	crt, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	ck := &Cert{
		Certificate: crt,
		Key:         eckey,
		IsCA:        true,
	}

	err = ca.db.StoreICA(ck)
	if err != nil {
		return nil, err
	}

	ica := &CA{
		Certificate: crt,
		key:         eckey,
		parent:      ca,
		db:          ca.db,
		clock:       ca.clock,
	}
	return ica, nil
}

// Return PEM encoded cert for this CA
func (ca *CA) PEM() []byte {
	p := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Raw,
	}

	return pem.EncodeToMemory(p)
}

// Return PEM encoded cert & key
func (ck *Cert) PEM() (crt, key []byte) {
	p := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ck.Raw,
	}

	return pem.EncodeToMemory(p), ck.Rawkey
}

// Return true if the CA hasn't expired and is not revoked
func (ca *CA) IsValid() bool {
	if ca.Expired || ca.CARevoked {
		return false
	}

	if ok, err := ca.isRevokedCA(ca.SubjectKeyId); err == nil && ok {
		ca.CARevoked = true
		return false
	}

	// we assume it's not revoked and check for expiry
	// if db is corrupt or inaccessible, we have a soft-fail here

	now := ca.clock.Now()
	if ca.NotAfter.Sub(now) <= _MinValidity {
		ca.Expired = true
		return false
	}
	return true
}

// -- CA internal functions --

func isRevoked(m map[string]*CA, rca *CA, skid []byte) bool {
	// walk up the chain of issuers to ensure everyone is still active
	ski := fmt.Sprintf("%x", skid)
	rki := fmt.Sprintf("%x", rca.SubjectKeyId)
	for ski != rki {
		x, ok := m[ski]
		if !ok {
			return true
		}
		ski = fmt.Sprintf("%x", x.AuthorityKeyId)
	}
	return false
}

// Return true if a given subjectKeyId belonging to a CA is revoked
func (ca *CA) isRevokedCA(skid []byte) (bool, error) {
	m, rca, err := ca.findCAs()
	if err != nil {
		// XXX Do we return true or false?
		// Right now, this is a soft-fail
		return false, err
	}

	if isRevoked(m, rca, skid) {
		return true, nil
	}

	return false, nil
}

type revoked struct {
	*Cert
	when time.Time
}

// validate a cert against expiry
func (ca *CA) validate(c *Cert) (*Cert, error) {
	now := ca.clock.Now()
	if c.NotAfter.Sub(now) <= _MinValidity {
		c.Expired = true
		return c, ErrExpired
	}

	return c, nil
}

// find all the signing entities in the system (including Root CA)
func (ca *CA) findCAs() (map[string]*CA, *CA, error) {
	// we always want to find the the root-ca
	ck, err := ca.db.GetRootCA()
	if err != nil {
		return nil, nil, fmt.Errorf("can't find root-CA: %w", err)
	}

	if ck, err = ca.validate(ck); err != nil {
		return nil, nil, err
	}

	rca := &CA{
		Certificate: ck.Certificate,
		key:         ck.Key,
		db:          ca.db,
		clock:       ca.clock,
	}
	rca.parent = rca

	assert(rca.key != nil, "root-ca key is nil")

	// map of SubjectKeyId to the cert
	m := make(map[string]*CA)

	rkid := fmt.Sprintf("%x", rca.SubjectKeyId)
	m[rkid] = rca

	err = ca.db.MapICA(func(s *Cert) error {
		key := fmt.Sprintf("%x", s.SubjectKeyId)
		s, err = ca.validate(s)
		if err != nil {
			// we skip this cert/ca and go to the next one.
			return nil
		}

		assert(s.Key != nil, "ica-ca %s key is nil", s.Subject.CommonName)
		m[key] = &CA{
			Certificate: s.Certificate,
			Expired:     s.Expired,
			key:         s.Key,
			db:          ca.db,
			clock:       ca.clock,
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("can't walk all CAs: %w", err)
	}

	// We need to fixup the parents for each CA instance in the map
	for _, s := range m {
		aki := fmt.Sprintf("%x", s.AuthorityKeyId)
		x, ok := m[aki]
		if !ok {
			s.CARevoked = true
			continue
		}
		s.parent = x
	}
	return m, rca, nil
}

// generate CRL
func (ca *CA) crl(crlValidDays int) ([]byte, error) {
	var rvc []pkix.RevokedCertificate

	rv, err := ca.ListRevoked()
	if err != nil {
		return nil, err
	}

	for _, c := range rv {
		rk := pkix.RevokedCertificate{
			SerialNumber:   c.SerialNumber,
			RevocationTime: c.When,
		}
		rvc = append(rvc, rk)
	}

	now := ca.clock.Now()
	exp := now.Add(time.Duration(crlValidDays) * 24 * time.Hour)
	der, err := ca.CreateCRL(rand.Reader, ca.key, rvc, now, exp)
	return der, err
}

// issue a new client or server cert
func (ca *CA) newCert(ci *CertInfo, pw string, isServer bool) (*Cert, error) {
	if !ca.IsValid() {
		return nil, ErrExpired
	}

	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("can't generate ECC P256 key: %w", err)
	}

	serial, err := ca.db.NewSerial()
	if err != nil {
		return nil, fmt.Errorf("can't generate new serial#: %w", err)
	}

	var val []byte
	var extKeyUsage x509.ExtKeyUsage

	if isServer {
		// nsCert = Client
		val, err = asn1.Marshal(asn1.BitString{Bytes: []byte{0x40}, BitLength: 2})
		if err != nil {
			return nil, fmt.Errorf("can't marshal nsCertType: %s", err)
		}
		extKeyUsage = x509.ExtKeyUsageServerAuth
	} else {

		// nsCert = Client
		val, err = asn1.Marshal(asn1.BitString{Bytes: []byte{0x80}, BitLength: 2})
		if err != nil {
			return nil, fmt.Errorf("can't marshal nsCertType: %s", err)
		}
		extKeyUsage = x509.ExtKeyUsageClientAuth
	}

	pubkey := eckey.Public().(*ecdsa.PublicKey)
	now := ca.clock.Now()
	csr := &x509.Certificate{
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
		PublicKeyAlgorithm:    x509.ECDSA,
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(ci.Validity)),
		SerialNumber:          serial,
		Issuer:                ca.Subject,
		Subject:               ci.Subject,
		BasicConstraintsValid: true,

		SubjectKeyId:   cksum(pubkey),
		AuthorityKeyId: ca.SubjectKeyId,

		DNSNames:       ci.DNSNames,
		IPAddresses:    ci.IPAddresses,
		EmailAddresses: ci.EmailAddresses,

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{extKeyUsage},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1},
				Value: val,
			},
		},
	}

	// Sign with CA's private key
	cn := ci.Subject.CommonName
	der, err := x509.CreateCertificate(rand.Reader, csr, ca.Certificate, pubkey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("%s: can't sign CSR: %w", cn, err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	ck := &Cert{
		Certificate: cert,
		Key:         eckey,
		Additional:  ci.Additional,
	}

	if isServer {
		err = ca.db.StoreServerCert(ck, pw)
	} else {
		err = ca.db.StoreClientCert(ck, pw)
	}

	if err != nil {
		return nil, err
	}

	return ck, nil
}

// create the root CA and update DB
func createRootCA(cfg *Config, clk clock, db Storage) (*Cert, error) {
	serial := db.GetSerial()

	eckey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: can't generate ECC P256 key: %s", err)
	}

	pubkey := eckey.Public().(*ecdsa.PublicKey)
	skid := cksum(pubkey)

	now := clk.Now()
	// Create the request template
	template := x509.Certificate{
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
		PublicKeyAlgorithm:    x509.ECDSA,
		SerialNumber:          serial,
		Issuer:                cfg.Subject,
		Subject:               cfg.Subject,
		NotBefore:             now,
		NotAfter:              now.Add(cfg.Validity),
		BasicConstraintsValid: true,
		IsCA:                  true,

		// We reserve the right to issue intermediate CAs. So, the path length
		// constraint must be "unset" (-1 ==> "unset")
		// In the future if this constraint is needed, provide it in the Config
		// object above and set this to the value from there.
		MaxPathLen: -1,

		// We're self signed; we set both
		SubjectKeyId:   skid,
		AuthorityKeyId: skid,

		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	// self-sign the certificate authority
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, pubkey, eckey)
	if err != nil {
		return nil, fmt.Errorf("ca: can't sign root CA cert: %s", err)
	}

	crt, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	ck := &Cert{
		Certificate: crt,
		Key:         eckey,
		IsCA:        true,
	}

	if err := db.StoreRootCA(ck); err != nil {
		return nil, err
	}

	return ck, nil
}

// Given a Cert, a raw key block and a password, decrypt the privatekey
// and set it to c.Key
func (c *Cert) decryptKey(key []byte, pw string) error {
	blk, _ := pem.Decode(key)

	var der []byte = blk.Bytes
	var err error

	if x509.IsEncryptedPEMBlock(blk) {
		pass := []byte(pw)
		der, err = x509.DecryptPEMBlock(blk, pass)
		if err != nil {
			return fmt.Errorf("can't decrypt private key (pw=%s): %s", pw, err)
		}
	}

	sk, err := x509.ParseECPrivateKey(der)
	if err == nil {
		c.Key = sk
	}

	return err
}

// given a Cert, marshal the private key and return as bytes
func (c *Cert) encryptKey(pw string) ([]byte, error) {
	if c.Key == nil {
		// XXX Do we validate if this exists?
		return c.Rawkey, nil
	}

	derkey, err := x509.MarshalECPrivateKey(c.Key)
	if err != nil {
		return nil, fmt.Errorf("can't marshal private key: %s", err)
	}

	var blk *pem.Block
	if len(pw) > 0 {
		pass := []byte(pw)
		blk, err = x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", derkey, pass, x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
	} else {
		blk = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: derkey,
		}
	}

	return pem.EncodeToMemory(blk), nil
}

// default system clock
type sysClock struct{}

func newSysClock() clock {
	c := &sysClock{}
	return c
}

func (c *sysClock) Now() time.Time {
	return time.Now().UTC()
}

func assert(cond bool, msg string, args ...interface{}) {
	if cond {
		return
	}

	_, file, line, ok := runtime.Caller(1)
	if !ok {
		file = "???"
		line = 0
	}

	s := fmt.Sprintf(msg, args...)
	s = fmt.Sprintf("%s:%d: Assertion failed!\n%s\n", file, line, s)
	panic(s)
}

// vim: ft=go:noexpandtab:sw=8:ts=8
