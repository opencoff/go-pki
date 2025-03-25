// json_test.go -- test harness for json import/export

package pki

import (
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestJsonv1Export(t *testing.T) {
	assert := newAsserter(t)

	td := newTmpDir()
	dbfile := td.newFile()

	defer func() {
		td.cleanup()
	}()

	clk0 := newDummyClock()
	dbc := &dbConfig{
		Name:   dbfile,
		Passwd: "pwd",
		Create: true,
	}
	bdb, err := openBoltDB(dbc, clk0)
	assert(err == nil, "can't create boltdb instance: %s", err)
	assert(bdb != nil, "boltdb is nil")

	cfg := &Config{
		Passwd: dbc.Passwd,
		Subject: pkix.Name{
			CommonName: "root-CA",
		},
		Validity: time.Duration(5 * time.Hour * 24),
	}
	cn := "a.example.com"
	ca, err := newWithClock(cfg, clk0, bdb, true)
	assert(err == nil, "ca create failed: %s", err)
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

	srvs, err := ca.GetServers()
	assert(err == nil, "can't find all servers: %s", err)
	assert(len(srvs) == 1, "server certs mismatch; exp 1, saw %d", len(srvs))

	clis, err := ca.GetClients()
	assert(err == nil, "can't find all clients: %s", err)
	assert(len(clis) == 1, "clients certs mismatch; exp 1, saw %d", len(clis))

	js, err := bdb.ExportJSON()
	assert(err == nil, "Can't export json: %s", err)

	// Now import into new store
	clk1 := newDummyClock()
	dbc2 := &dbConfig{
		Name:   td.newFile(),
		Passwd: "123",
		Create: true,
		Json:   js,
	}
	bdb2, err := openBoltDB(dbc2, clk1)
	assert(err == nil, "can't create 2nd boltdb: %s", err)
	assert(bdb2 != nil, "db2 nil!")

	cfg.Passwd = dbc2.Passwd
	ca2, err := newWithClock(cfg, clk1, bdb2, true)
	assert(err == nil, "ca create failed: %s", err)
	assert(ca2 != nil, "ca2 is nil")

	// validate that root-ca is same
	assert(byteEq(ca.SubjectKeyId, ca2.SubjectKeyId), "CA mismatch after import")

	srv2, err := ca2.GetServers()
	assert(err == nil, "can't get ca2-servers: %s", err)
	assert(len(srvs) == len(srv2), "server certs mismatch; exp %d, saw %d", len(srvs), len(srv2))

	cli2, err := ca2.GetClients()
	assert(err == nil, "can't get ca2-clients: %s", err)
	assert(len(clis) == len(cli2), "client certs mismatch; exp %d, saw %d", len(clis), len(cli2))
}
