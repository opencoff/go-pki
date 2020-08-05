// json_test.go -- test harness for json import/export

package pki

import (
	"crypto/x509/pkix"
	"fmt"
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

func TestJsonImport(t *testing.T) {
	assert := newAsserter(t)
	td := newTmpDir()

	defer func() {
		td.cleanup()
	}()

	// Now import into new store
	clk1 := newDummyClock()
	dbc2 := &dbConfig{
		Name:   td.newFile(),
		Passwd: "123",
		Create: true,
		Json:   jsonStr,
	}
	bdb2, err := openBoltDB(dbc2, clk1)
	assert(err == nil, "can't create boltdb from json: %s", err)
	assert(bdb2 != nil, "db2 nil!")

	cfg := &Config{
		Passwd: dbc2.Passwd,
	}
	ca2, err := newWithClock(cfg, clk1, bdb2, true)
	assert(err == nil, "ca create failed: %s", err)
	assert(ca2 != nil, "ca2 is nil")

	defer ca2.Close()

	srv, err := ca2.GetServers()
	assert(err == nil, "get-servers: %s", err)
	assert(len(srv) == 2, "get-servers: exp 2, saw %d", len(srv))

	_, err = ca2.FindServer("proxy.example.com")
	assert(err == nil, "can't find proxy: %s", err)

	_, err = ca2.FindServer("foo.example.com")
	assert(err == nil, "can't find foo: %s", err)

	cli, err := ca2.GetClients()
	assert(err == nil, "get-clients: %s", err)
	assert(len(cli) == 3, "get-clients: exp 2, saw %d", len(cli))

	// we know we should find 3 clients and 2 servers
	clients := []string{"u0", "u1", "u3"}
	for _, p := range clients {
		cn := fmt.Sprintf("%s@example.com", p)
		_, err := ca2.FindClient(cn)
		assert(err == nil, "can't find %s: %s", cn, err)
	}

	// u3@example.com has an encrypted key
	ck, err := ca2.FindClient("u3@example.com")
	assert(err == nil, "can't find u3: %s", err)
	assert(ck.Key == nil, "wrapped key decrypted?")
	assert(ck.Rawkey != nil, "no raw key?")
}

const jsonStr string = `{
    "Config": {
        "Salt": "pqkb0NC7A8Nkhe6ckjin8/SVS4ErZDFqQl5Oj4nU6wk=",
        "Rawkey": "EkfCNS6WyQYrsj11sUFiZ7667bDLa7xtYvfa92N171I=",
        "Serial": "ATriDjOI/z9i3rgAyj9IvGE=",
        "Cert": "-----BEGIN CERTIFICATE-----\nMIIB5zCCAY2gAwIBAgIRATriDjOI/z9i3rgAyj9IvFwwCgYIKoZIzj0EAwQwNTEL\nMAkGA1UEBhMCVVMxCTAHBgNVBAoTADEJMAcGA1UECxMAMRAwDgYDVQQDEwdyb290\nLWNhMB4XDTIwMDgwNDAwNDUyMloXDTI1MDgwMzA2NDYyMlowNTELMAkGA1UEBhMC\nVVMxCTAHBgNVBAoTADEJMAcGA1UECxMAMRAwDgYDVQQDEwdyb290LWNhMFkwEwYH\nKoZIzj0CAQYIKoZIzj0DAQcDQgAEWg4LQf+0Hq82Z9ubxqhNZY4Z48PgzdbycKCy\nK5C4oWEpDE3GiD7HiAaUiRLgND4t9gxSW7Z4NHljt0QdjmTVFKN+MHwwDgYDVR0P\nAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwKQYDVR0OBCIEIGovC/0EoRLb\nzPJOzV3fGYyxzzqmFtgVaFwOKTsaNDinMCsGA1UdIwQkMCKAIGovC/0EoRLbzPJO\nzV3fGYyxzzqmFtgVaFwOKTsaNDinMAoGCCqGSM49BAMEA0gAMEUCIGK2GjshLI17\nTDFTBkBewvHDfFETsf1AWEugPPYFQRhXAiEAgIc+uVW/W52sE4G+gMc3TnML0B2a\nJ3X1yNZNJ77hvDQ=\n-----END CERTIFICATE-----\n",
        "Key": "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,f6e5170315fb9b87d749ec950425a2f3\n\nZ1pKy7F98Mk2q9/4SpXv22bpRB0vOceiRJN0LX/9cqeZsnhGr24frQSE2WtXOVDU\nNnsb9cc5McWhs/6dAxmRgNrjxs/mDHOjp1JNshVWshXGeFCzQl1YQa9ecTSvtyON\n6PvkRtDNeLBmlP/anCv1nDTvkampsadOhZzxl+SsTgQ=\n-----END EC PRIVATE KEY-----\n"
    },
    "Servers": [
        {
            "Cert": "-----BEGIN CERTIFICATE-----\nMIICLjCCAdWgAwIBAgIRATriDjOI/z9i3rgAyj9IvF0wCgYIKoZIzj0EAwQwNTEL\nMAkGA1UEBhMCVVMxCTAHBgNVBAoTADEJMAcGA1UECxMAMRAwDgYDVQQDEwdyb290\nLWNhMB4XDTIwMDgwNDAwNDUzMFoXDTIyMDgwNDA2NDYzMFowPTELMAkGA1UEBhMC\nVVMxCTAHBgNVBAoTADEJMAcGA1UECxMAMRgwFgYDVQQDEw9mb28uZXhhbXBsZS5j\nb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS28L2EUrabotkXmmCT384pIRYw\nSO3t405Q4IxfmgDowS5nVAXUwJgsxdKhJdo4n91iG7s3KiHoCvM6HQhDkp/fo4G9\nMIG6MA4GA1UdDwEB/wQEAwIDqDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMB\nAf8EAjAAMCkGA1UdDgQiBCAjagUQ79R68rtui/3+Gl3ABrf+jv8Ke8YwQcK9e2vL\nOjArBgNVHSMEJDAigCBqLwv9BKES28zyTs1d3xmMsc86phbYFWhcDik7GjQ4pzAa\nBgNVHREEEzARgg9mb28uZXhhbXBsZS5jb20wEQYJYIZIAYb4QgEBBAQDAgZAMAoG\nCCqGSM49BAMEA0cAMEQCICzi8LkHf7jXNwQss+hTv6RMqW9XTCkTBA3ud1NjL8To\nAiAtEWEP3snbmDGI8iKsI0hF06Nqw4Mx5k/7mcOogn1H9w==\n-----END CERTIFICATE-----\n",
            "Key": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIK6GhcUVYlxAp1mihq+DLBuoTufTUY3beLepuQH9eDD8oAoGCCqGSM49\nAwEHoUQDQgAEtvC9hFK2m6LZF5pgk9/OKSEWMEjt7eNOUOCMX5oA6MEuZ1QF1MCY\nLMXSoSXaOJ/dYhu7Nyoh6ArzOh0IQ5Kf3w==\n-----END EC PRIVATE KEY-----\n",
            "Additional": "Jv+BAwEBB3NydmRhdGEB/4IAAQIBBFBvcnQBBgABA1RMUwEKAAAA/gEL/4IB/gSqAf4BAONDTRpcmN3yBlmAjmVgnBOxmlsXdYFLA55HgdhLH0s2MhJ0GMA2c3dq4QOqPttUIG9U09/AvVmjL4yBtJZCllTaqQr6JuaoFxf9HtNRFsaaQdJXsRxsdbf0yDCV4wekk25iG+6iGF71r+ByZx29eu98lNnLg6u4MU252BJrxgoquBlm/wvDfd8Z3IdVlBOfSIYOQnLe01+ABSTgql3002fhgU+m+2gEydWEXQKT1vfLKvCKo7HjiHSipzwCH7ScDik9n7nPWJd7Q+fyhx7DfgPjCKgcsoo0NHmGyUehLvvDlvuYKSs8VjRb0KOQJylMbXBxtazGetttea4QBreHUq0A"
        },
        {
            "Cert": "-----BEGIN CERTIFICATE-----\nMIICMzCCAdmgAwIBAgIRATriDjOI/z9i3rgAyj9IvF4wCgYIKoZIzj0EAwQwNTEL\nMAkGA1UEBhMCVVMxCTAHBgNVBAoTADEJMAcGA1UECxMAMRAwDgYDVQQDEwdyb290\nLWNhMB4XDTIwMDgwNDAwNDUzN1oXDTIyMDgwNDA2NDYzN1owPzELMAkGA1UEBhMC\nVVMxCTAHBgNVBAoTADEJMAcGA1UECxMAMRowGAYDVQQDExFwcm94eS5leGFtcGxl\nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEdNiB6zft6l/FdXNwLJ7b06\nNcUzEp1uclLgTS7+3Faahkhu1CU0fBwoldRLaGsB88QVuc6k6+gk9mOzpIFmY5Oj\ngb8wgbwwDgYDVR0PAQH/BAQDAgOoMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1Ud\nEwEB/wQCMAAwKQYDVR0OBCIEINgtrTQoM3WZvKFU51hZnqyREtTqXaRsMPwu1wdl\nW92IMCsGA1UdIwQkMCKAIGovC/0EoRLbzPJOzV3fGYyxzzqmFtgVaFwOKTsaNDin\nMBwGA1UdEQQVMBOCEXByb3h5LmV4YW1wbGUuY29tMBEGCWCGSAGG+EIBAQQEAwIG\nQDAKBggqhkjOPQQDBANIADBFAiAXfNI6a9QqOZfOLx5MEIPbzB+8Jwh843qr19o0\nx3f+wQIhAPBvln3bPryNUyy7hqj/GOzWpLRz4O2pWKryiOpS3nq3\n-----END CERTIFICATE-----\n",
            "Key": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIKGA61iolTtndp39ZScEU5Ac6JGOvkn99+lceQCXhAmRoAoGCCqGSM49\nAwEHoUQDQgAER02IHrN+3qX8V1c3AsntvTo1xTMSnW5yUuBNLv7cVpqGSG7UJTR8\nHCiV1EtoawHzxBW5zqTr6CT2Y7OkgWZjkw==\n-----END EC PRIVATE KEY-----\n",
            "Additional": "Jv+BAwEBB3NydmRhdGEB/4IAAQIBBFBvcnQBBgABA1RMUwEKAAAA/gEL/4IB/gSqAf4BALQZAz0pbG16xuzeYnV9wRUDCh/Iy0Ud7ekkkS6ipJoNCY21nbaUD9HsdxMd9vpuxWhoxWS0pcVIvF78YsO7XEMCZ7loYJi9AaIXxYhA8dldt/ruohbqqfCZK22HOAKIXELKaDjWraWzAqrEpulrytn6RnMWVvUAe+xxGj0L3LgrFKAmWmG2IwvR6z/S3qJTpxXpoYkB+7P2DH6d7QHyDrqMemmitJF4tGuiSNaUcLKQC7Q8l9ZbJiaz6zp5pyg6uZkwk770xZZ3S480BG8YWDQ7hGw5UtrQWgo5t0yntS59YDNyft5edWyqRW2M9yi3OdbdMbaVg1yL76GfiWl+S/0A"
        }
    ],
    "Clients": [
        {
            "Cert": "-----BEGIN CERTIFICATE-----\nMIICLjCCAdOgAwIBAgIRATriDjOI/z9i3rgAyj9IvGAwCgYIKoZIzj0EAwQwNTEL\nMAkGA1UEBhMCVVMxCTAHBgNVBAoTADEJMAcGA1UECxMAMRAwDgYDVQQDEwdyb290\nLWNhMB4XDTIwMDgwNDAwNDU0OFoXDTIyMDgwNDA2NDY0OFowPDELMAkGA1UEBhMC\nVVMxCTAHBgNVBAoTADEJMAcGA1UECxMAMRcwFQYDVQQDDA51MUBleGFtcGxlLmNv\nbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHfJXhMxv3oN/8A3+u3VyWnj0s3m\nqWt2pTB4VRX6h5XUAdNSlyWlx2i0ayLAf3a1OUu51SlKmjqO+b+H7ZznW02jgbww\ngbkwDgYDVR0PAQH/BAQDAgOoMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB\n/wQCMAAwKQYDVR0OBCIEILkwZSF+mU1ioqoOMQvW4kAW+ByumlpNlfzhIkkw3kIT\nMCsGA1UdIwQkMCKAIGovC/0EoRLbzPJOzV3fGYyxzzqmFtgVaFwOKTsaNDinMBkG\nA1UdEQQSMBCBDnUxQGV4YW1wbGUuY29tMBEGCWCGSAGG+EIBAQQEAwIGgDAKBggq\nhkjOPQQDBANJADBGAiEA1DqleIqmXfSycWHcVmsTb6lt7iu5pxRT0useo6kT07sC\nIQCVZlgNQ+UPSzxwae9jOE9Fy6veE9goImOD6woyfTNYDQ==\n-----END CERTIFICATE-----\n",
            "Key": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIH5f4Lv65UhMcpgts1NzGufxP3rmSuxjCDtCJPnNoNUVoAoGCCqGSM49\nAwEHoUQDQgAEd8leEzG/eg3/wDf67dXJaePSzeapa3alMHhVFfqHldQB01KXJaXH\naLRrIsB/drU5S7nVKUqaOo75v4ftnOdbTQ==\n-----END EC PRIVATE KEY-----\n"
        },
        {
            "Cert": "-----BEGIN CERTIFICATE-----\nMIICLTCCAdOgAwIBAgIRATriDjOI/z9i3rgAyj9IvGEwCgYIKoZIzj0EAwQwNTEL\nMAkGA1UEBhMCVVMxCTAHBgNVBAoTADEJMAcGA1UECxMAMRAwDgYDVQQDEwdyb290\nLWNhMB4XDTIwMDgwNDAwNTUyMVoXDTIyMDgwNDA2NTYyMVowPDELMAkGA1UEBhMC\nVVMxCTAHBgNVBAoTADEJMAcGA1UECxMAMRcwFQYDVQQDDA51M0BleGFtcGxlLmNv\nbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABClwlvztzEn/qqFMhXAH2v9XQMgs\ntY7f6Drfs2xpqwGx6HdMeHsPjS9LceotQ9dIAhegCknGgt3/XClUHIQtDx+jgbww\ngbkwDgYDVR0PAQH/BAQDAgOoMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB\n/wQCMAAwKQYDVR0OBCIEIEu+EA0XJ14+A8w3fYQTA4TmBFO+JqLyick2OKRp+qHZ\nMCsGA1UdIwQkMCKAIGovC/0EoRLbzPJOzV3fGYyxzzqmFtgVaFwOKTsaNDinMBkG\nA1UdEQQSMBCBDnUzQGV4YW1wbGUuY29tMBEGCWCGSAGG+EIBAQQEAwIGgDAKBggq\nhkjOPQQDBANIADBFAiBBHKwVEwpkGzJrhZyLY9HOvUBULHo1K32VwsoRm2EE4AIh\nAPcKxB2sBRKTRb31m9+7Ga2Ry+tJECHitUzDle7QKGPh\n-----END CERTIFICATE-----\n",
            "Key": "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,6736eb1e66b93733d64b93be3cb30154\n\nU1wRkF78K+YPLAAfasEY2anI8oAhQ+0SYtAOikAX+CG7MB7YvNuiEddZcWcPeZyQ\n8ep2Vuglc/EzYHWESS0stu00xz88yA6EQ6CmAOAwquzT7UehP0Xw/ThUYu7BFCTc\nHJ82F2ywOiaCuQHufe9kLIfJscyS4kj7h/iYprWQd2g=\n-----END EC PRIVATE KEY-----\n"
        },
        {
            "Cert": "-----BEGIN CERTIFICATE-----\nMIICLjCCAdOgAwIBAgIRATriDjOI/z9i3rgAyj9IvF8wCgYIKoZIzj0EAwQwNTEL\nMAkGA1UEBhMCVVMxCTAHBgNVBAoTADEJMAcGA1UECxMAMRAwDgYDVQQDEwdyb290\nLWNhMB4XDTIwMDgwNDAwNDU0NFoXDTIyMDgwNDA2NDY0NFowPDELMAkGA1UEBhMC\nVVMxCTAHBgNVBAoTADEJMAcGA1UECxMAMRcwFQYDVQQDDA51MEBleGFtcGxlLmNv\nbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBpUb0D/NrLVYZJfQi6EwTATYFTi\nID1p69rLT9ww+YbxeSTzDZ7Zp/xdtUhFM6iDmisXqI4h3D3IWPlBUk2Yyqejgbww\ngbkwDgYDVR0PAQH/BAQDAgOoMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB\n/wQCMAAwKQYDVR0OBCIEIKSG4HLUPJEPCjv17FBpgknD39kN6ZtekJ8+tl37Jpq3\nMCsGA1UdIwQkMCKAIGovC/0EoRLbzPJOzV3fGYyxzzqmFtgVaFwOKTsaNDinMBkG\nA1UdEQQSMBCBDnUwQGV4YW1wbGUuY29tMBEGCWCGSAGG+EIBAQQEAwIGgDAKBggq\nhkjOPQQDBANJADBGAiEAwKwvgtanHRI0nr8FqducQ9Tz5TP3jfaeb1a9Hd7ELAAC\nIQC/LSY4COeLvuxjsFv0HuhU7zS1BWmuUVTz8iEPffbJKQ==\n-----END CERTIFICATE-----\n",
            "Key": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIAbrFOo4FdYhBK+pLULdocbWNBS26RgAyegAUyudAW43oAoGCCqGSM49\nAwEHoUQDQgAEGlRvQP82stVhkl9CLoTBMBNgVOIgPWnr2stP3DD5hvF5JPMNntmn\n/F21SEUzqIOaKxeojiHcPchY+UFSTZjKpw==\n-----END EC PRIVATE KEY-----\n"
        }
    ],
    "Icas": [],
    "Revoked": []
}`
