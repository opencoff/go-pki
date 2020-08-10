// jsonv1.go - JSON Export for DB Version #1
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"math/big"
	"time"
)

type jsonv1Dump struct {
	Config  jsonv1Config
	Servers []*jsonv1CertKey
	Clients []*jsonv1CertKey
	CAs     []*jsonv1CertKey
	Revoked []*jsonv1Revoked
}

type jsonv1Config struct {
	Version uint32 `json:",omitempty"`
	Salt    []byte
	Rawkey  []byte
	Cert    string
	Key     string
	Serial  []byte
}

type jsonv1CertKey struct {
	Cert       string
	Key        string
	Additional []byte `json:",omitempty"`
}

type jsonv1Revoked struct {
	Cert string
	When time.Time
}

// Export DB _properties_ as a JSON blob
func (d *db) ExportJSON() (string, error) {
	rca, err := d.GetRootCA()
	if err != nil {
		return "", err
	}

	ckpem, keypem := rca.PEM()

	jsrv := make([]*jsonv1CertKey, 0, 4)
	jcli := make([]*jsonv1CertKey, 0, 4)
	jcas := make([]*jsonv1CertKey, 0, 4)
	revs := make([]*jsonv1Revoked, 0, 4)

	toJson := func(c *Cert, v []*jsonv1CertKey) []*jsonv1CertKey {
		cpem, kpem := c.PEM()
		js := &jsonv1CertKey{
			Cert:       string(cpem),
			Key:        string(kpem),
			Additional: c.Additional,
		}
		v = append(v, js)
		return v
	}

	err = d.mapCerts("server", func(c *Cert) error {
		jsrv = toJson(c, jsrv)
		return nil
	})
	if err != nil {
		return "", err
	}

	err = d.mapCerts("client", func(c *Cert) error {
		jcli = toJson(c, jcli)
		return nil
	})
	if err != nil {
		return "", err
	}

	err = d.mapCerts("ica", func(c *Cert) error {
		jcas = toJson(c, jcas)
		return nil
	})
	if err != nil {
		return "", err
	}

	err = d.MapRevoked(func(t time.Time, c *Cert) {
		cpem, _ := c.PEM()
		js := &jsonv1Revoked{
			Cert: string(cpem),
			When: t,
		}
		revs = append(revs, js)
	})
	if err != nil {
		return "", err
	}

	jv := &jsonv1Dump{
		Config: jsonv1Config{
			Version: DBVersion,
			Salt:    d.salt,
			Rawkey:  d.pwd,
			Cert:    string(ckpem),
			Key:     string(keypem),
			Serial:  d.serial.Bytes(),
		},
		Servers: jsrv,
		Clients: jcli,
		CAs:     jcas,
		Revoked: revs,
	}

	js, err := json.Marshal(jv)
	if err != nil {
		return "", fmt.Errorf("json: can't marshal: %w", err)
	}

	return string(js), nil
}

// import a v1 json blob
func (d *db) importJsonV1(jc *jsonv1Dump) error {

	// We can throw away the incoming salt, db key and just use the certs...
	// - The root-CA priv key is encrypted using db.key:
	//     key = sprintf("%x", db.key)
	//     eckey = decrypt_PEM(wrapped_ca_key, key)
	// - We will compute the largest serial# we've seen and use that - we don't want to blindly
	//   trust the serial# in the incoming JSON
	root, err := parseJsonv1RootCertKey(&jc.Config)
	if err != nil {
		fmt.Printf("can't parse root key: %s\n", err)
		return err
	}

	var serial *big.Int = big.NewInt(0).SetBytes(jc.Config.Serial)
	if serial.Cmp(root.SerialNumber) < 0 {
		return fmt.Errorf("json: root-ca serial# is malformed")
	}

	// Update everything in a single transaction
	err = d.db.Update(func(tx *bolt.Tx) error {
		cfg := tx.Bucket([]byte("config"))
		srv := tx.Bucket([]byte("server"))
		cli := tx.Bucket([]byte("client"))
		cab := tx.Bucket([]byte("ica"))
		rev := tx.Bucket([]byte("revoked"))

		if cfg == nil || srv == nil || cli == nil || cab == nil || rev == nil {
			return fmt.Errorf("json: can't find buckets")
		}

		st := updateState{
			d:      d,
			root:   root,
			serial: serial,
			err:    nil,
		}

		st.storeAll(srv, jc.Servers)
		st.storeAll(cli, jc.Clients)
		st.storeAll(cab, jc.CAs)
		st.storeRevoked(rev, jc.Revoked)
		st.storeFinal(cfg)

		return st.err
	})

	d.serial = serial
	return err
}

type updateState struct {
	d      *db
	root   *Cert
	serial *big.Int
	err    error
}

func (st *updateState) storeAll(b *bolt.Bucket, certs []*jsonv1CertKey) {
	if st.err != nil {
		return
	}

	for i := range certs {
		cs := certs[i]
		c, err := parseJsonv1CertKey(cs)
		if err != nil {
			fmt.Printf("can't parse cert key: %s\n", err)
			st.err = err
			return
		}

		if c.SerialNumber.Cmp(st.serial) > 0 {
			st.serial = c.SerialNumber
		}

		eb, err := st.prepare(c)
		if err != nil {
			fmt.Printf("can't prepare cert key: %s\n", err)
			st.err = err
			return
		}

		cn := c.Subject.CommonName
		err = b.Put(st.d.key(cn), eb)
		if err != nil {
			fmt.Printf("can't store cert key: %s\n", err)
			st.err = err
			return
		}
	}
}

func (st *updateState) storeRevoked(rb *bolt.Bucket, revs []*jsonv1Revoked) {
	if st.err != nil {
		return
	}

	for i := range revs {
		var b bytes.Buffer
		r := revs[i]

		blk, _ := pem.Decode([]byte(r.Cert))
		ck, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			st.err = fmt.Errorf("json: can't decode revoked-cert: %w", err)
			return
		}

		rg := revokedgob{
			Cert: []byte(r.Cert),
			When: r.When,
		}
		g := gob.NewEncoder(&b)
		err = g.Encode(&rg)
		if err != nil {
			st.err = fmt.Errorf("json: can't gob encode revoked: %w", err)
			return
		}
		eb, err := st.d.encrypt(b.Bytes())
		if err != nil {
			st.err = err
			return
		}
		rkey := fmt.Sprintf("%x", ck.SubjectKeyId)
		err = rb.Put(st.d.key(rkey), eb)
		if err != nil {
			st.err = err
			return
		}
	}
}

func (st *updateState) storeFinal(cfg *bolt.Bucket) {
	if st.err != nil {
		return
	}
	reb, err := st.prepare(st.root)
	if err != nil {
		return
	}

	seb, err := st.d.encrypt(st.serial.Bytes())
	if err != nil {
		st.err = err
		return
	}

	err = cfg.Put(st.d.key("ca"), reb)
	if err != nil {
		st.err = err
		return
	}

	st.err = cfg.Put(st.d.key("serial"), seb)
}

func (st *updateState) prepare(c *Cert) ([]byte, error) {
	b, err := st.d.marshalCert(c, "")
	if err != nil {
		st.err = err
		return nil, err
	}

	eb, err := st.d.encrypt(b)
	if err != nil {
		st.err = err
	}
	return eb, err
}

func (d *db) importJson(s string) error {
	var jc jsonv1Dump

	err := json.Unmarshal([]byte(s), &jc)
	if err != nil {
		return fmt.Errorf("can't decode json: %w", err)
	}

	// version 0 or missing version# implies the old DB format
	// v0 and v1 have roughly the same format for storing artifacts.
	// So, we can use the same common routine..
	switch jc.Config.Version {
	case 0, 1:
		return d.importJsonV1(&jc)
	default:
		return fmt.Errorf("json: no support to import version %d", jc.Config.Version)
	}

}

func parseJsonv1RootCertKey(jc *jsonv1Config) (*Cert, error) {
	blk, _ := pem.Decode([]byte(jc.Key))
	var der []byte = blk.Bytes
	if x509.IsEncryptedPEMBlock(blk) {
		var err error
		pwd := fmt.Sprintf("%x", jc.Rawkey)
		der, err = x509.DecryptPEMBlock(blk, []byte(pwd))
		if err != nil {
			return nil, fmt.Errorf("json: can't decrypt root EC key: %w", err)
		}
	}

	sk, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("json: can't parse root EC Key: %w", err)
	}

	blk, _ = pem.Decode([]byte(jc.Cert))
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}

	c := &Cert{
		Certificate: crt,
		Key:         sk,
	}
	return c, nil
}

// parse json blob into a cert structure
func parseJsonv1CertKey(jc *jsonv1CertKey) (*Cert, error) {
	blk, _ := pem.Decode([]byte(jc.Cert))
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}

	c := &Cert{
		Certificate: crt,
		Additional:  jc.Additional,
	}

	blk, _ = pem.Decode([]byte(jc.Key))
	if !x509.IsEncryptedPEMBlock(blk) {
		sk, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		c.Key = sk
	}
	c.Rawkey = []byte(jc.Key)
	return c, nil
}
