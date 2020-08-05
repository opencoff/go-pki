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
//   random 32-byte key (via AEAD AES-256-GCM) "db.key". We also store
//   a 32-byte salt used for KDF and other enc/dec operations.
// * This DB key is stored in an encrypted form in the DB; it is encrypted
//   with a user supplied passphrase:
//     db.key = randbytes(32)
//     db.salt = randbytes(32)
//     expanded = SHA512(passphrase)
//     kek = KDF(expanded, db.salt)
//     esk = AES-256-GCM(db.key, kek)
//  * EC Private keys are optionally encrypted with a user supplied passphrase
//    (if provided) before being stored in the DB
//  * Almost _all_ artifacts stored in the DB are AEAD encrypted:
//     nonce = randbytes(16)
//     kdfsalt = sha256(nonce, db.salt)
//     encKey =  HKDF(db.key, kdfsalt)
//     encbytes = AES-256-GCM(plaintext, enckey, nonce)
//  * The only artifacts not encrypted are:
//     DB Version
//     Salt
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
	"crypto/x509"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	bolt "github.com/etcd-io/bbolt"
	"math/big"
	"os"
	"path"
	"sync"
	"time"
)

// DB Version. This must be updated whenever we change the schema
const DBVersion uint32 = 1

type dbConfig struct {
	Name   string
	Passwd string

	Json   string
	Create bool
}

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
func openBoltDB(dbc *dbConfig, clk clock) (Storage, error) {
	fn := dbc.Name
	fi, _ := os.Stat(fn)
	switch {
	case fi == nil:
		if !dbc.Create {
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

	var epw [sha512.Size]byte

	h := sha512.New()
	h.Write([]byte(dbc.Passwd))
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

		// create or read as appropriate

		skey := []byte("salt")
		pkey := []byte("ekey")
		nkey := []byte("serial")
		vkey := []byte("version")

		b := tx.Bucket([]byte("config"))
		if b == nil {
			return fmt.Errorf("%s: can't find config bucket", fn)
		}

		salt := b.Get(skey)
		ekey := b.Get(pkey)
		sbytes := b.Get(nkey)
		ver := b.Get(vkey)
		if len(ver) == 0 && (len(salt) > 0 || len(ekey) > 0 || len(sbytes) > 0) {
			return fmt.Errorf("Old version of DB; please upgrade DB")
		}

		d.salt = make([]byte, 32)
		if salt == nil || ekey == nil || sbytes == nil || ver == nil {
			var vers [4]byte

			d.pwd = make([]byte, 32)
			d.serial = randSerial()

			binary.LittleEndian.PutUint32(vers[:], DBVersion)
			ver := vers[:]

			// generate a random DB key and encrypt it with the user supplied key
			randbytes(d.pwd)
			randbytes(d.salt)

			kek := kdf(expanded, d.salt)

			ekey, err := aeadEncrypt(d.pwd, kek, d.salt, ver)
			if err != nil {
				return fmt.Errorf("%s: can't encrypt DB password: %w", fn, err)
			}

			sbytes, err = d.encrypt(d.serial.Bytes())
			if err != nil {
				return fmt.Errorf("root-ca: can't encrypt serial#: %w", err)
			}

			if err = b.Put(skey, d.salt); err != nil {
				return fmt.Errorf("%s: can't write salt: %w", fn, err)
			}
			if err = b.Put(pkey, ekey); err != nil {
				return fmt.Errorf("%s: can't write E-key: %w", fn, err)
			}

			if err = b.Put(nkey, sbytes); err != nil {
				return fmt.Errorf("%s: can't write serial: %w", fn, err)
			}

			if err = b.Put(vkey, vers[:]); err != nil {
				return fmt.Errorf("%s: can't write version#: %w", fn, err)
			}

			return nil
		}

		if len(salt) != 32 || len(ver) != 4 {
			return fmt.Errorf("DB corrupt; salt/version# malformed")
		}

		// check the version#
		dbver := binary.LittleEndian.Uint32(ver)
		if dbver != DBVersion {
			return fmt.Errorf("%s: Incorrect DB version (exp %d, saw %d)", fn, DBVersion, dbver)
		}

		// This may be an initialized DB. Lets verify it.
		kek := kdf(expanded, salt)

		key, err := aeadDecrypt(ekey, kek, salt, ver)
		if err != nil {
			return fmt.Errorf("%s: wrong password?", fn)
		}

		// we have to copy the salt -- it will be unmapped after this transaction ends
		copy(d.salt, salt)
		d.pwd = key

		// we need the passwd & salt initialized before this decrypt.
		sb, err := d.decrypt(sbytes)
		if err != nil {
			return fmt.Errorf("%s: can't decrypt serial: %s", fn, err)
		}
		d.serial = big.NewInt(0).SetBytes(sb)
		return nil
	})

	if len(dbc.Json) > 0 {
		err = d.importJson(dbc.Json)
	}

	// Always return the DB; we need to properly close it regardless of error.
	return d, err
}

// Change the DB encryption key to 'newpw'
func (d *db) Rekey(newpw string) error {
	var epw [sha512.Size]byte
	var vers [4]byte

	h := sha512.New()
	h.Write([]byte(newpw))
	expanded := h.Sum(epw[:0])
	kek := kdf(expanded, d.salt)

	binary.LittleEndian.PutUint32(vers[:], DBVersion)
	ekey, err := aeadEncrypt(d.pwd, kek, d.salt, vers[:])
	if err != nil {
		return fmt.Errorf("rekey: can't re-encrypt DB password: %w", err)
	}

	err = d.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("config"))
		if b == nil {
			return ErrNoConfigBucket
		}

		if err := b.Put([]byte("ekey"), ekey); err != nil {
			return fmt.Errorf("rekey: can't write encrypted-key: %w", err)
		}
		return nil
	})
	return err
}

// close the DB. No other methods can work without re-opening the db
func (d *db) Close() error {
	// wipe the keys
	for i := range d.pwd {
		d.pwd[i] = 0
	}
	d.pwd = nil
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

	return z, d.storeSerial(d.serial)
}

// Fetch the root CA
func (d *db) GetRootCA() (*Cert, error) {
	var c *Cert

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

		err = c.decryptKey(c.Rawkey, "")
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
	b, err := d.marshalCert(c, "")
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
	ck, err := d.getCert(nm, "ica", "")
	if err != nil {
		return nil, err
	}

	ck.IsCA = true
	return ck, nil
}

// Store the given intermediate CA
func (d *db) StoreICA(c *Cert) error {
	return d.storeCert(c, "ica", "")
}

// Fetch the given client cert
func (d *db) GetClientCert(nm string, pw string) (*Cert, error) {
	return d.getCert(nm, "client", pw)
}

// Store the given client cert
func (d *db) StoreClientCert(c *Cert, pw string) error {
	return d.storeCert(c, "client", pw)
}

// Fetch the given server cert
func (d *db) GetServerCert(nm string, pw string) (*Cert, error) {
	return d.getCert(nm, "server", pw)
}

// Store the given server cert
func (d *db) StoreServerCert(c *Cert, pw string) error {
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
			if table == "ica" {
				// ICA's don't use any password
				err = c.decryptKey(c.Rawkey, "")
				if err != nil {
					return fmt.Errorf("%s: can't decrypt key: %w", table, err)
				}
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
	b, err := d.marshalCert(c, pw)
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
			Cert: gb,
			When: d.clock.Now(),
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

// marshal a Cert into a gob stream
func (d *db) marshalCert(c *Cert, pw string) ([]byte, error) {
	sn := c.Subject.CommonName
	if c.Raw == nil {
		return nil, fmt.Errorf("%s: Raw cert is nil?", sn)
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

// store the given serial# in the DB
func (d *db) storeSerial(serial *big.Int) error {
	es, err := d.encrypt(serial.Bytes())
	if err != nil {
		return fmt.Errorf("update-serial: %w", err)
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

	return err
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
