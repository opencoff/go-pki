// boltdb.go - db storage for certs, server info etc. using boltDB instance
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package pki

// Internal details:
//
// * All data written to the db is encrypted with a key derived from a
//   random 32-byte key.
// * This DB key is stored in an encrypted form in the DB; it is encrypted
//   with a user supplied passphrase:
//     dbkey = randbytes(32)
//     expanded = SHA512(passphrase)
//     kek = KDF(expanded, salt)
//     esk = kek ^ dbkey
//
// * Updating serial#: anytime a user cert or a server cert is written,
//   we update the serial number at the same time. We also update serial
//   number when CA is created for the first time.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"fmt"
	bolt "github.com/etcd-io/bbolt"
	"math/big"
	"os"
	"path"
	"sync"
	"time"
)

type db struct {
	db   *bolt.DB
	pwd  []byte // expanded 64 byte passphrase
	salt []byte // KDF salt

	mu     sync.RWMutex
	serial *big.Int

	clock clock

	// set to true if CA has been initialized
	initialized bool
}

type cadata struct {
	Cert
	serial *big.Int
}


type revokedgob struct {
	// encrypted, gob-encoded cert block
	Cert []byte

	When time.Time
}

// gob encoded Cert pair
type certgob struct {
	Cert []byte
	Key  []byte

	Additional []byte
}

// Create or open a boltbd instance containing the certs
func openBoltDB(fn string, clk clock, pw string, creat bool) (Storage, error) {
	fi, _ := os.Stat(fn)
	switch {
	case fi == nil:
		if !creat {
			return nil, fmt.Errorf("can't open DB %s", fn)
		}
		dbdir := path.Dir(fn)
		err := os.MkdirAll(dbdir, 0700)
		if err != nil {
			return nil, fmt.Errorf("%s: can't create dir %s: %w", fn, dbdir, err)
		}

	case fi != nil:
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%s: not a regular file", fn)
		}
	}

	bdb, err := bolt.Open(fn, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("db %s: %w", fn, err)
	}

	var salt []byte
	var pwd [32]byte
	var saltb [32]byte
	var epw [sha512.Size]byte

	h := sha512.New()
	h.Write([]byte(pw))
	expanded := h.Sum(epw[:0])

	buckets := []string{
		"config",
		"server",
		"client",
		"ica",
		"revoked",
	}

	d := &db{
		db:    bdb,
		clock: clk,
	}

	// initialize key buckets
	err = bdb.Update(func(tx *bolt.Tx) error {
		for i := range buckets {
			nm := buckets[i]
			bu := []byte(nm)
			_, err := tx.CreateBucketIfNotExists(bu)
			if err != nil {
				return fmt.Errorf("%s: can't create %s: %w", fn, nm, err)
			}
		}

		skey := []byte("salt")
		ckey := []byte("check")
		pkey := []byte("ekey")
		nkey := []byte("serial")

		var cksum [sha256.Size]byte
		var serial *big.Int

		b := tx.Bucket([]byte("config"))
		if b == nil {
			return fmt.Errorf("%s: can't find config bucket", fn)
		}

		salt = b.Get(skey)
		chk := b.Get(ckey)
		ekey := b.Get(pkey)
		sbytes := b.Get(nkey)
		if salt == nil || chk == nil || ekey == nil || sbytes == nil ||
			len(ekey) != 32 || len(chk) != sha256.Size || len(salt) != 32 {
			
			var ekeyb [32]byte
			var err error

			serial = randSerial()
			ekey = ekeyb[:]

			// generate a random DB key and encrypt it with the user supplied key

			randbytes(pwd[:])
			salt = randbytes(saltb[:])
			kek := kdf(expanded, salt)
			for i := 0; i < 32; i++ {
				ekey[i] = kek[i] ^ pwd[i]
			}

			d.salt = salt
			d.pwd = pwd[:]
			d.serial = serial

			h := sha256.New()
			h.Write(salt)
			h.Write(kek)
			chk = h.Sum(cksum[:0])

			sbytes, err = d.encrypt(serial.Bytes())
			if err != nil {
				return fmt.Errorf("root-ca: can't encrypt serial#: %w", err)
			}

			if err = b.Put(skey, salt); err != nil {
				return fmt.Errorf("%s: can't write salt: %w", fn, err)
			}
			if err = b.Put(ckey, chk); err != nil {
				return fmt.Errorf("%s: can't write checksum: %w", fn, err)
			}
			if err = b.Put(pkey, ekey[:]); err != nil {
				return fmt.Errorf("%s: can't write E-key: %w", fn, err)
			}

			if err = b.Put(nkey, sbytes); err != nil {
				return fmt.Errorf("%s: can't write serial: %w", fn, err)
			}

			return nil
		}

		// This may be an initialized DB. Lets verify it.
		kek := kdf(expanded, salt)

		h := sha256.New()
		h.Write(salt)
		h.Write(kek)
		vrfy := h.Sum(cksum[:0])

		if subtle.ConstantTimeCompare(chk, vrfy) != 1 {
			return fmt.Errorf("%s: wrong password", fn)
		}

		// finally decode the encrypted DB key
		for i := 0; i < 32; i++ {
			pwd[i] = ekey[i] ^ kek[i]
		}

		d.salt = salt
		d.pwd = pwd[:]

		// we need the passwd & salt initialized before this decrypt.
		sb, err := d.decrypt(sbytes)
		if err != nil {
			return fmt.Errorf("%s: can't decrypt serial: %s", fn, err)
		}
		d.serial = big.NewInt(0).SetBytes(sb)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return d, nil
}

// Change the DB encryption key to 'newpw'
func (d *db) Rekey(newpw string) error {
	var pwb [sha512.Size]byte
	var cksum [sha256.Size]byte
	var ekey [32]byte

	h := sha512.New()
	h.Write([]byte(newpw))
	newpwd := h.Sum(pwb[:0])

	// New KEK
	kek := kdf(newpwd, d.salt)
	for i := 0; i < 32; i++ {
		ekey[i] = kek[i] ^ d.pwd[i]
		kek[i] = 0
	}

	h = sha256.New()
	h.Write(d.salt)
	h.Write(kek)
	chk := h.Sum(cksum[:0])

	err := d.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("config"))
		if b == nil {
			return ErrNoConfigBucket
		}

		ckey := []byte("check")
		pkey := []byte("ekey")

		if err := b.Put(ckey, chk); err != nil {
			return fmt.Errorf("rekey: can't write checksum: %w", err)
		}

		if err := b.Put(pkey, ekey[:]); err != nil {
			return fmt.Errorf("rekey: can't write E-key: %w", err)
		}
		return nil
	})
	return err
}

// close the DB. No other methods can work without re-opening the db
func (d *db) Close() error {
	// wipe the keys
	for i := 0; i < 32; i++ {
		d.pwd[i] = 0
	}
	d.salt = nil
	d.serial = nil
	return d.db.Close()
}

func (d *db) GetSerial() *big.Int {
	d.mu.RLock()

	var z big.Int
	z.Set(d.serial)
	d.mu.RUnlock()

	return &z
}

// increment the serial number and update the db
func (d *db) NewSerial() (*big.Int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	z := big.NewInt(1)
	d.serial.Add(d.serial, z)
	z.Set(d.serial)

	es, err := d.encrypt(d.serial.Bytes())
	if err != nil {
		return nil, fmt.Errorf("update-serial: %w", err)
	}

	err = d.db.Update(func(tx *bolt.Tx) error {
		bu := tx.Bucket([]byte("config"))
		if bu == nil {
			return ErrNoConfigBucket
		}

		if err := bu.Put([]byte("serial"), es); err != nil {
			return fmt.Errorf("update-serial: %w", err)
		}
		return nil
	})

	return z, err
}

// Fetch the root CA
func (d *db) GetRootCA() (*Cert, error) {
	var c *Cert

	pw := fmt.Sprintf("%x", d.pwd)
	err := d.db.View(func(tx *bolt.Tx) error {
		bc := tx.Bucket([]byte("config"))
		if bc == nil {
			return ErrNoConfigBucket
		}

		eb := bc.Get(d.key("ca"))
		if eb == nil {
			return nil
		}

		gb, err := d.decrypt(eb)
		if err != nil {
			return fmt.Errorf("root-ca: can't decrypt: %w", err)
		}

		c, err = d.unmarshalCert("root-ca", gb)
		if err != nil {
			return fmt.Errorf("root-ca: can't decode: %w", err)
		}

		err = c.decryptKey(c.Rawkey, pw)
		if err != nil {
			return fmt.Errorf("root-ca: can't decrypt key: %w", err)
		}

		c.IsCA = true
		return nil
	})

	return c, err
}

// Store a new root CA
func (d *db) StoreRootCA(c *Cert) error {
	pw := fmt.Sprintf("%x", d.pwd)
	b, err := c.marshal(pw)
	if err != nil {
		return fmt.Errorf("root-ca: can't marshal: %w", err)
	}

	eb, err := d.encrypt(b)
	if err != nil {
		return fmt.Errorf("root-ca: can't encrypt: %w", err)
	}

	err = d.db.Update(func(tx *bolt.Tx) error {
		bc := tx.Bucket([]byte("config"))
		if bc == nil {
			return ErrNoConfigBucket
		}

		err := bc.Put(d.key("ca"), eb)
		if err != nil {
			return fmt.Errorf("can't write ca data: %w", err)
		}

		return nil
	})
	return err
}

// Fetch given intermediate CA
func (d *db) GetICA(nm string) (*Cert, error) {

	pw := fmt.Sprintf("%x", d.pwd)
	ck, err := d.getCert(nm, "ica", pw)
	if err != nil {
		return nil, err
	}

	ck.IsCA = true
	return ck, nil
}

// Store the given intermediate CA
func (d *db) StoreICA(c *Cert) error {
	pw := fmt.Sprintf("%x", d.pwd)
	return d.storeCert(c, "ica", pw)
}

// Fetch the given client cert
func (d *db) GetClientCert(nm string, pw string) (*Cert, error) {
	ck, err := d.getCert(nm, "client", pw)
	if err != nil {
		return nil, err
	}
	return ck, nil
}

// Store the given client cert
func (d *db) StoreClientCert(c *Cert, pw string) error {
	if len(pw) == 0 {
		pw = fmt.Sprintf("%x", d.pwd)
	}

	return d.storeCert(c, "client", pw)
}

// Fetch the given server cert
func (d *db) GetServerCert(nm string, pw string) (*Cert, error) {
	ck, err := d.getCert(nm, "server", pw)
	if err != nil {
		return nil, err
	}
	return ck, nil
}

// Store the given server cert
func (d *db) StoreServerCert(c *Cert, pw string) error {
	if len(pw) == 0 {
		pw = fmt.Sprintf("%x", d.pwd)
	}
	return d.storeCert(c, "server", pw)
}

// Delete given intermediate CA
func (d *db) DeleteICA(nm string) error {
	return d.delCert(nm, "ica")
}

// Delete the given client cert
func (d *db) DeleteClientCert(nm string) error {
	return d.delCert(nm, "client")
}

// Delete the given server cert
func (d *db) DeleteServerCert(nm string) error {
	return d.delCert(nm, "server")
}

// Iterate over all intermediate certs
func (d *db) MapICA(fp func(c *Cert) error) error {
	return d.mapCerts("ica", fp)
}

// Iterate over all client certs
func (d *db) MapClientCerts(fp func(c *Cert) error) error {
	return d.mapCerts("client", fp)
}

// Iterate over all server certs
func (d *db) MapServerCerts(fp func(c *Cert) error) error {
	return d.mapCerts("server", fp)
}

// Iterate over all revoked certs
func (d *db) MapRevoked(fp func(t time.Time, c *Cert)) error {
	err := d.db.View(func(tx *bolt.Tx) error {
		bs := tx.Bucket([]byte("revoked"))
		if bs == nil {
			return fmt.Errorf("can't find revoked bucket")
		}

		err := bs.ForEach(func(k, ev []byte) error {
			var rv revokedgob

			ub, err := d.decrypt(ev)
			if err != nil {
				return fmt.Errorf("can't decrypt revoked data: %w", err)
			}

			b := bytes.NewBuffer(ub)
			g := gob.NewDecoder(b)
			err = g.Decode(&rv)
			if err != nil {
				return fmt.Errorf("can't decode revoked data: %w", err)
			}

			// we now decode the cert
			ck, err := d.unmarshalCert("$revoked", rv.Cert)
			if err != nil {
				return fmt.Errorf("can't decode revoked cert: %w", err)
			}

			fp(rv.When, ck)
			return nil
		})
		return err
	})
	return err
}

// find a revoked cert by SubjectKeyId
func (d *db) FindRevoked(skid []byte) (time.Time, *Cert, error) {
	var ck *Cert
	var when time.Time

	key := fmt.Sprintf("%x", skid)
	err := d.db.View(func(tx *bolt.Tx) error {
		bu := tx.Bucket([]byte("revoked"))
		if bu == nil {
			return fmt.Errorf("can't find revoked bucket")
		}

		eb := bu.Get(d.key(key))
		if eb == nil {
			return ErrNotFound
		}

		var rv revokedgob
		ub, err := d.decrypt(eb)
		if err != nil {
			return fmt.Errorf("can't decrypt revoked data: %w", err)
		}

		b := bytes.NewBuffer(ub)
		g := gob.NewDecoder(b)
		err = g.Decode(&rv)
		if err != nil {
			return fmt.Errorf("can't decode revoked data: %w", err)
		}

		// we now decode the cert
		ck, err = d.unmarshalCert("$revoked", rv.Cert)
		if err != nil {
			return fmt.Errorf("can't decode revoked cert: %w", err)
		}
		when = rv.When
		return nil
	})

	return when, ck, err
}

// -- helper functions --


// iterate over all certs in a given bucket
func (d *db) mapCerts(table string, fp func(c *Cert) error) error {
	err := d.db.View(func(tx *bolt.Tx) error {
		bu := tx.Bucket([]byte(table))
		if bu == nil {
			return fmt.Errorf("can't find %s bucket", table)
		}

		err := bu.ForEach(func(k, ev []byte) error {
			v, err := d.decrypt(ev)
			if err != nil {
				return fmt.Errorf("%s: can't decrypt cert info: %s", table, err)
			}

			c, err := d.unmarshalCert("$cert", v)
			if err != nil {
				return fmt.Errorf("%s: can't unmarshal cert: %w", table, err)
			}
			if table == "server" {
				c.IsServer = true
			}

			fp(c)
			return nil
		})

		return err
	})

	return err
}

func (d *db) storeCert(c *Cert, table, pw string) error {
	cn := c.Subject.CommonName
	b, err := c.marshal(pw)
	if err != nil {
		return fmt.Errorf("%s: can't marshal cert: %w", cn, err)
	}

	eb, err := d.encrypt(b)
	if err != nil {
		return fmt.Errorf("%s: can't encrypt cert: %w", cn, err)
	}

	err = d.db.Update(func(tx *bolt.Tx) error {
		bc := tx.Bucket([]byte(table))
		if bc == nil {
			return fmt.Errorf("%s: can't find bucket %s", cn, table)
		}

		err := bc.Put(d.key(cn), eb)
		if err != nil {
			return fmt.Errorf("%s: can't write: %w", cn, err)
		}

		return nil
	})

	return err
}

func (d *db) getCert(cn, table, pw string) (*Cert, error) {
	var ck *Cert

	err := d.db.View(func(tx *bolt.Tx) error {
		bc := tx.Bucket([]byte(table))
		if bc == nil {
			return fmt.Errorf("%s: can't find bucket %s", cn, table)
		}

		eb := bc.Get(d.key(cn))
		if eb == nil {
			return ErrNotFound
		}

		gb, err := d.decrypt(eb)
		if err != nil {
			return fmt.Errorf("%s: can't decrypt cert: %w", cn, err)
		}

		ck, err = d.unmarshalCert(cn, gb)
		if err != nil {
			return fmt.Errorf("%s: can't decode cert: %w", cn, err)
		}

		if len(pw) > 0 {
			err = ck.decryptKey(ck.Rawkey, pw)
		}
		return err
	})

	return ck, err
}

// delete the given cert from the named table
func (d *db) delCert(cn string, table string) error {
	err := d.db.Update(func(tx *bolt.Tx) error {
		bc := tx.Bucket([]byte(table))
		if bc == nil {
			return fmt.Errorf("%s: can't find bucket %s", cn, table)
		}

		rv := tx.Bucket([]byte("revoked"))
		if rv == nil {
			return fmt.Errorf("%s: can't find revoked bucket", cn)
		}

		key := d.key(cn)
		eb := bc.Get(key)
		if eb == nil {
			return ErrNotFound
		}

		gb, err := d.decrypt(eb)
		if err != nil {
			return fmt.Errorf("%s: can't decrypt cert: %w", cn, err)
		}

		ck, err := d.unmarshalCert(cn, gb)
		if err != nil {
			return fmt.Errorf("%s: can't decode cert: %w", cn, err)
		}

		rg := revokedgob{
			Cert:	gb,
			When:   d.clock.Now(),
		}

		var b bytes.Buffer
		g := gob.NewEncoder(&b)
		err = g.Encode(&rg)
		if err != nil {
			return fmt.Errorf("%s: can't gob encode: %w", cn, err)
		}

		er, err := d.encrypt(b.Bytes())
		if err != nil {
			return fmt.Errorf("%s: can't encrypt revoked data: %w", cn, err)
		}

		// Add the cert on the revoked list. We'll use this to list revoked certs
		// and generate an up-to-date CRL.
		rkey := fmt.Sprintf("%x", ck.SubjectKeyId)
		err = rv.Put(d.key(rkey), er)
		if err != nil {
			return fmt.Errorf("%s: can't add to revoked bucket: %w", cn, err)
		}

		return bc.Delete(key)
	})

	return err
}

// Decode a serialized cert/key pair
func (d *db) unmarshalCert(cn string, ub []byte) (*Cert, error) {
	var cg certgob

	b := bytes.NewBuffer(ub)
	g := gob.NewDecoder(b)
	err := g.Decode(&cg)
	if err != nil {
		return nil, fmt.Errorf("%s: can't decode gob: %s", cn, err)
	}
	cert, err := x509.ParseCertificate(cg.Cert)
	if err != nil {
		return nil, fmt.Errorf("%s: can't parse cert: %s", cn, err)
	}

	now := d.clock.Now()
	exp := cert.NotAfter
	diff := exp.Sub(now)

	var expired bool = diff <= _MinValidity

	ck := &Cert{
		Certificate: cert,
		Rawkey:      cg.Key,
		Expired:     expired,
		Additional:  cg.Additional,
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
		return nil, fmt.Errorf("privatkey is nil")
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

// marshal a Cert into a gob stream
func (c *Cert) marshal(pw string) ([]byte, error) {
	sn := c.Subject.CommonName
	if c.Raw == nil {
		return nil, fmt.Errorf("%s: Raw cert is nil?", sn)
	}
	if len(pw) == 0 {
		return nil, fmt.Errorf("%s: Enc key is empty", sn)
	}

	key, err := c.encryptKey(pw)
	if err != nil {
		return nil, err
	}

	cg := &certgob{
		Cert:       c.Raw,
		Key:        key,
		Additional: c.Additional,
	}

	var b bytes.Buffer
	g := gob.NewEncoder(&b)
	err = g.Encode(cg)
	if err != nil {
		return nil, fmt.Errorf("%s: can't gob-encode cert: %s", sn, err)
	}

	return b.Bytes(), nil
}

// hash publickey; we use it as a salt for encryption and also SubjectKeyId
func cksum(pk *ecdsa.PublicKey) []byte {
	pm := elliptic.Marshal(pk.Curve, pk.X, pk.Y)
	return hash(pm)
}

func hash(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

func randSerial() *big.Int {
	min := big.NewInt(1)
	min.Lsh(min, 120)

	max := big.NewInt(1)
	max.Lsh(max, 130)

	for {
		serial, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(fmt.Errorf("ca: can't generate serial#: %w", err))
		}

		if serial.Cmp(min) > 0 {
			return serial
		}
	}
	panic("can't gen new CA serial")
}

var (
	ErrNoConfigBucket = errors.New("db: can't find config bucket")
	ErrNotFound       = errors.New("no such CN")
	ErrTooSmall       = errors.New("decrypt: input buffer too small")
	ErrExpired        = errors.New("certificate has expired")
	ErrCARevoked      = errors.New("issuing CA is revoked")
)

// vim: ft=go:noexpandtab:sw=8:ts=8
