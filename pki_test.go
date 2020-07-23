// pki_test.go - test harness for PKI

package pki

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestCreate(t *testing.T) {
	assert := newAsserter(t)
	clk := newDummyClock()
	db := newRamStore(clk)

	cfg := &Config{
		Passwd: "",
		Subject: pkix.Name{
			CommonName: "root-CA",
		},
		Validity: time.Duration(2 * time.Hour * 24),
	}

	ca, err := newWithClock(cfg, clk, db, false)
	assert(err != nil, "first time create should fail")
	assert(ca == nil, "ca is not nil")

	ca, err = newWithClock(cfg, clk, db, true)
	assert(err == nil, "ca create failed")
	assert(ca != nil, "ca is nil")
	assert(ca.Certificate != nil, "ca.cert is nil")
}

func TestBasic(t *testing.T) {
	assert := newAsserter(t)

	dir, dbfile := tmpFile()

	defer func() {
		os.RemoveAll(dir)
	}()

	clk0 := newDummyClock()
	clk1 := newDummyClock()
	rdb := newRamStore(clk0)
	bdb, err := openBoltDB(dbfile, clk1, "pwd", true)
	assert(err == nil, "can't create boltdb instance")
	assert(bdb != nil, "boltdb is nil")

	t.Run("ramDB", func(t *testing.T) {
		t.Parallel()
		testBasic(rdb, clk0, t)
	})
	t.Run("BoltDB", func(t *testing.T) {
		t.Parallel()
		testBasic(bdb, clk1, t)
	})
}

func TestICA0(t *testing.T) {
	assert := newAsserter(t)

	dir, dbfile := tmpFile()

	defer func() {
		os.RemoveAll(dir)
	}()

	clk0 := newDummyClock()
	clk1 := newDummyClock()
	rdb := newRamStore(clk0)
	bdb, err := openBoltDB(dbfile, clk1, "pwd", true)
	assert(err == nil, "can't create boltdb instance")
	assert(bdb != nil, "boltdb is nil")

	t.Run("ramDB", func(t *testing.T) {
		t.Parallel()
		testCA0(rdb, clk0, t)
	})
	t.Run("BoltDB", func(t *testing.T) {
		t.Parallel()
		testCA0(bdb, clk1, t)
	})
}

func TestICA1(t *testing.T) {
	assert := newAsserter(t)

	dir, dbfile := tmpFile()

	defer func() {
		os.RemoveAll(dir)
	}()

	clk0 := newDummyClock()
	clk1 := newDummyClock()
	rdb := newRamStore(clk0)
	bdb, err := openBoltDB(dbfile, clk1, "pwd", true)
	assert(err == nil, "can't create boltdb instance")
	assert(bdb != nil, "boltdb is nil")

	t.Run("ramDB", func(t *testing.T) {
		t.Parallel()
		testCA1(rdb, clk0, t)
	})
	t.Run("BoltDB", func(t *testing.T) {
		t.Parallel()
		testCA1(bdb, clk1, t)
	})
}

func TestRevokeCA(t *testing.T) {
	assert := newAsserter(t)

	dir, dbfile := tmpFile()

	defer func() {
		os.RemoveAll(dir)
	}()

	clk0 := newDummyClock()
	clk1 := newDummyClock()
	rdb := newRamStore(clk0)
	bdb, err := openBoltDB(dbfile, clk1, "pwd", true)
	assert(err == nil, "can't create boltdb instance")
	assert(bdb != nil, "boltdb is nil")

	t.Run("ramDB", func(t *testing.T) {
		t.Parallel()
		testRevokeCA(rdb, clk0, t)
	})
	t.Run("BoltDB", func(t *testing.T) {
		t.Parallel()
		testRevokeCA(bdb, clk1, t)
	})
}

func testRevokeCA(db Storage, clk *dummyClock, t *testing.T) {
	assert := newAsserter(t)

	cfg := &Config{
		Passwd: "",
		Subject: pkix.Name{
			CommonName: "root-CA",
		},
		Validity: time.Duration(5 * time.Hour * 24),
	}

	ca, err := newWithClock(cfg, clk, db, true)
	assert(err == nil, "ca create failed")
	assert(ca != nil, "ca is nil")
	assert(ca.Certificate != nil, "ca.cert is nil")

	// we should NOT be allowed to revoke the root CA
	err = ca.RevokeCA(ca.Subject.CommonName)
	assert(err == ErrNotFound, "revoke root-ca: %s", err)

	ci := &CertInfo{
		Validity: time.Duration(25 * time.Hour),
	}

	ci.Subject.CommonName = "intermediate-ca-1"
	ica, err := ca.NewIntermediateCA(ci)
	assert(err == nil, "intermediate ca#1 fail: %s", err)
	assert(ica != nil, "intermediate ca#1 nil")

	ci.Subject.CommonName = "intermediate-ca-2"
	ica2, err := ica.NewIntermediateCA(ci)
	assert(err == nil, "intermediate ca#2 fail: %s", err)
	assert(ica2 != nil, "intermediate ca#2 nil")

	cn := "user@example.com"
	ci = &CertInfo{
		Subject: pkix.Name{
			CommonName: cn,
		},
		Validity: time.Duration(25 * time.Hour),
	}

	ck, err := ica2.NewClientCert(ci, "")
	assert(err == nil, "can't create client cert: %s", err)
	assert(ck != nil, "new client cert is nil")

	// Now revoke top-level ica and fetch the client cert
	err = ca.RevokeCA(ica.Subject.CommonName)
	assert(err == nil, "revoke ica: %s", err)

	ck, err = ca.FindClient(cn)
	assert(ck.CARevoked, "signing CA not revoked")
	assert(err == ErrCARevoked, "%s not revoked: %s", cn, err)
	assert(ck != nil, "client cert nil")

	xca, err := ca.FindCA(ica.Subject.CommonName)
	assert(err == ErrNotFound, "revoked CA err: %s", err)
	assert(xca == nil, "revoked CA is non nil")

	ok, err := ca.IsRevokedCA(ica)
	assert(err == nil, "ica revoke: %s", err)
	assert(ok, "ica not revoked")

	// ica2 should now be invalid
	xca, err = ca.FindCA(ica2.Subject.CommonName)
	assert(err == ErrCARevoked, "ica not revoked: %s", err)
	assert(xca == nil, "xca non nil")

}

func testBasic(db Storage, clk *dummyClock, t *testing.T) {
	assert := newAsserter(t)

	cfg := &Config{
		Passwd: "",
		Subject: pkix.Name{
			CommonName: "root-CA",
		},
		Validity: time.Duration(5 * time.Hour * 24),
	}

	cn := "a.example.com"
	ca, err := newWithClock(cfg, clk, db, true)
	assert(err == nil, "ca create failed")
	assert(ca != nil, "ca is nil")
	assert(ca.Certificate != nil, "ca.cert is nil")

	ci := &CertInfo{
		Subject: pkix.Name{
			CommonName: cn,
		},
		Validity: time.Duration(25 * time.Hour),
		DNSNames: []string{cn},
	}

	ck, err := ca.NewServerCert(ci, "")
	assert(err == nil, "can't create server cert: %s", err)
	assert(ck != nil, "new server cert is nil")

	cx, err := ca.FindServer(cn)
	assert(err == nil, "can't find newly created cert: %s", err)
	assert(cx != nil, "server cert is nil")

	assert(byteEq(ck.SubjectKeyId, cx.SubjectKeyId), "skid key mismatch:\nwant %x\nhave %x\n", ck.SubjectKeyId, cx.SubjectKeyId)
	assert(byteEq(ck.AuthorityKeyId, cx.AuthorityKeyId), "akid key mismatch:\nwant %x\nhave %x\n", ck.AuthorityKeyId, cx.AuthorityKeyId)

	// advance time to verify expiry
	clk.advanceDay(2)

	assert(ca.IsValid(), "premature ca expiry")

	cx, err = ca.FindServer(cn)
	assert(err == ErrExpired, "wrong error: %s", err)

	cn = "user@example.com"
	ci = &CertInfo{
		Subject: pkix.Name{
			CommonName: cn,
		},
		Validity: time.Duration(25 * time.Hour),
	}
	ck, err = ca.NewClientCert(ci, "")
	assert(err == nil, "can't create client cert: %s", err)
	assert(ck != nil, "new client cert is nil")

	cx, err = ca.FindClient(cn)
	assert(err == nil, "can't find newly created client cert: %s", err)
	assert(cx != nil, "client cert is nil")

	assert(byteEq(ck.SubjectKeyId, cx.SubjectKeyId), "skid key mismatch:\nwant %x\nhave %x\n", ck.SubjectKeyId, cx.SubjectKeyId)
	assert(byteEq(ck.AuthorityKeyId, cx.AuthorityKeyId), "akid key mismatch:\nwant %x\nhave %x\n", ck.AuthorityKeyId, cx.AuthorityKeyId)

	clk.advanceDay(4)
	assert(!ca.IsValid(), "ca should have expired")
}

func testCA0(db Storage, clk *dummyClock, t *testing.T) {
	assert := newAsserter(t)

	cfg := &Config{
		Passwd: "",
		Subject: pkix.Name{
			CommonName: "root-CA",
		},
		Validity: time.Duration(5 * time.Hour * 24),
	}

	cacn := "client-ca"
	ca, err := newWithClock(cfg, clk, db, true)
	assert(err == nil, "ca create failed")
	assert(ca != nil, "ca is nil")
	assert(ca.Certificate != nil, "ca.cert is nil")

	ci := &CertInfo{
		Subject: pkix.Name{
			CommonName: cacn,
		},
		Validity: time.Duration(25 * time.Hour),
	}

	ica, err := ca.NewIntermediateCA(ci)
	assert(err == nil, "intermediate ca fail: %s", err)
	assert(ica != nil, "intermediate ca nil")

	ica2, err := ca.FindCA(cacn)
	assert(err == nil, "can't find ica %s: %s", cacn, err)
	assert(ica2 != nil, "ica is nil")
	assert(ica2.IsValid(), "ica has expired")
	assert(byteEq(ica2.SubjectKeyId, ica.SubjectKeyId), "find-ca returned wrong CA")

	clk.advanceSec(300)

	cas, err := ca.GetCAs()
	assert(err == nil, "can't list all CAs")
	assert(len(cas) == 2, "#CA mismatch; exp 2, saw %d", len(cas))

	cas, err = ica.GetCAs()
	assert(err == nil, "can't list all CAs via ICA")
	assert(len(cas) == 2, "#CA via ICA mismatch; exp 2, saw %d", len(cas))

	for i := 0; i < 5; i++ {
		cn := fmt.Sprintf("user%d@example.com", i)
		sn := fmt.Sprintf("server%d.example.com", i)
		ci = &CertInfo{
			Subject: pkix.Name{
				CommonName: cn,
			},
			Validity: time.Duration(25 * time.Hour),
		}

		ck, err := ica.NewClientCert(ci, "")
		assert(err == nil, "can't create client cert: %s", err)
		assert(ck != nil, "new client cert nil")

		ck, err = ica.FindClient(cn)
		assert(err == nil, "can't find client cert: %s", err)
		assert(ck != nil, "client cert nil")

		clk.advanceSec(30)
		ci.Subject.CommonName = sn
		ci.DNSNames = []string{sn}
		sk, err := ica.NewServerCert(ci, "")
		assert(err == nil, "can't create server cert: %s", err)
		assert(sk != nil, "new server cert nil")

		sk, err = ica.FindServer(sn)
		assert(err == nil, "can't find server cert: %s", err)
		assert(sk != nil, "server cert nil")
	}

	ckc, err := ca.GetClients()
	assert(err == nil, "can't get all clients: %s", err)
	assert(len(ckc) == 5, "#client certs mismatch: exp 5, saw %d", len(ckc))
	cks, err := ca.GetServers()
	assert(err == nil, "can't get all servers: %s", err)
	assert(len(cks) == 5, "#server certs mismatch: exp 5, saw %d", len(cks))
}

func testCA1(db Storage, clk *dummyClock, t *testing.T) {
	assert := newAsserter(t)

	cfg := &Config{
		Passwd: "",
		Subject: pkix.Name{
			CommonName: "root-CA",
		},
		Validity: time.Duration(5 * time.Hour * 24),
	}

	ca, err := newWithClock(cfg, clk, db, true)
	assert(err == nil, "ca create failed")
	assert(ca != nil, "ca is nil")
	assert(ca.Certificate != nil, "ca.cert is nil")

	ci := &CertInfo{
		Subject: pkix.Name{
			CommonName: "intermediate-ca-1",
		},
		Validity: time.Duration(25 * time.Hour),
	}

	ica, err := ca.NewIntermediateCA(ci)
	assert(err == nil, "intermediate ca#1 fail: %s", err)
	assert(ica != nil, "intermediate ca#1 nil")

	ci.Subject.CommonName = "intermediate-ca-2"
	ica2, err := ica.NewIntermediateCA(ci)
	assert(err == nil, "intermediate ca#2 fail: %s", err)
	assert(ica2 != nil, "intermediate ca#2 nil")

	ci.Subject.CommonName = "intermediate-ca-3"
	ica3, err := ica2.NewIntermediateCA(ci)
	assert(err == nil, "intermediate ca#3 fail: %s", err)
	assert(ica3 != nil, "intermediate ca#3 nil")

	clk.advanceSec(300)

	cas, err := ca.GetCAs()
	assert(err == nil, "can't list all CAs")
	assert(len(cas) == 4, "#CA mismatch; exp 4, saw %d", len(cas))

	cn := "user@example.com"
	ci = &CertInfo{
		Subject: pkix.Name{
			CommonName: cn,
		},
		Validity: time.Duration(25 * time.Hour),
	}
	ck, err := ica3.NewClientCert(ci, "")
	assert(err == nil, "can't create client cert: %s", err)
	assert(ck != nil, "new client cert is nil")

	cas, err = ca.ChainFor(ck)
	assert(err == nil, "Can't find chain for client cert: %s", err)
	assert(len(cas) == 4, "cert chain len != 4, saw %d", len(cas))

	assert(byteEq(ck.AuthorityKeyId, cas[0].SubjectKeyId),     "issuer #0 mismatch")
	assert(byteEq(ck.AuthorityKeyId, ica3.SubjectKeyId),       "issuer #0 mismatch")

	assert(byteEq(cas[0].AuthorityKeyId, cas[1].SubjectKeyId), "issuer #1 mismatch")
	assert(byteEq(cas[0].AuthorityKeyId, ica2.SubjectKeyId),   "issuer #1 mismatch")

	assert(byteEq(cas[1].AuthorityKeyId, cas[2].SubjectKeyId), "issuer #2 mismatch")
	assert(byteEq(cas[1].AuthorityKeyId, ica.SubjectKeyId),    "issuer #1 mismatch")

	assert(byteEq(cas[2].AuthorityKeyId, cas[3].SubjectKeyId), "issuer #3 mismatch")
	assert(byteEq(cas[2].AuthorityKeyId, ca.SubjectKeyId),	   "issuer root mismatch")
}


func tmpFile() (string, string) {
	dir, err := ioutil.TempDir("", "bdb")
	if err != nil {
		panic(err)
	}

	var b [6]byte

	n, err := rand.Read(b[:])
	if err != nil || n != len(b) {
		panic("can't read rand")
	}

	return dir, fmt.Sprintf("%s/test_%x.db", dir, b[:])
}
