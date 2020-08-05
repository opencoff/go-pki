// mocks_test.go - mock storage & time provider

package pki

import (
	"fmt"
	"math/big"
	"sync"
	"time"
)

type ram struct {
	sync.Mutex
	root *Cert

	serial  *big.Int
	clients map[string]*Cert
	servers map[string]*Cert
	ica     map[string]*Cert

	revoked map[string]revoked

	clock clock
}

func newRamStore(clk clock) *ram {
	r := &ram{
		serial:  big.NewInt(0xdeadbeef),
		clock:   clk,
		clients: make(map[string]*Cert),
		servers: make(map[string]*Cert),
		ica:     make(map[string]*Cert),
		revoked: make(map[string]revoked),
	}
	return r
}

// -- Storage interface implementation --

func (r *ram) Rekey(newpw string) error {
	return nil
}

func (r *ram) Close() error {
	return nil
}

func (r *ram) GetRootCA() (*Cert, error) {
	r.Lock()
	defer r.Unlock()
	return r.root, nil
}

func (r *ram) StoreRootCA(c *Cert) error {
	r.Lock()
	defer r.Unlock()

	r.root = c
	return nil
}

func (r *ram) GetSerial() *big.Int {
	r.Lock()
	defer r.Unlock()
	return r.serial
}

func (r *ram) NewSerial() (*big.Int, error) {
	r.Lock()
	defer r.Unlock()
	z := big.NewInt(1)
	r.serial.Add(r.serial, z)
	z.Set(r.serial)
	return z, nil
}

func (r *ram) GetICA(nm string) (*Cert, error) {
	r.Lock()
	defer r.Unlock()
	c, ok := r.ica[nm]
	if !ok {
		return nil, ErrNotFound
	}
	return c, nil
}

func (r *ram) GetClientCert(nm string, pw string) (*Cert, error) {
	r.Lock()
	defer r.Unlock()
	c, ok := r.clients[nm]
	if !ok {
		return nil, ErrNotFound
	}
	return c, nil
}

func (r *ram) GetServerCert(nm string, pw string) (*Cert, error) {
	r.Lock()
	defer r.Unlock()
	c, ok := r.servers[nm]
	if !ok {
		return nil, ErrNotFound
	}
	return c, nil
}

func (r *ram) StoreICA(c *Cert) error {
	r.Lock()
	defer r.Unlock()
	r.ica[c.Subject.CommonName] = c
	return nil
}

func (r *ram) StoreClientCert(c *Cert, pw string) error {
	r.Lock()
	defer r.Unlock()
	r.clients[c.Subject.CommonName] = c
	return nil
}

func (r *ram) StoreServerCert(c *Cert, pw string) error {
	r.Lock()
	defer r.Unlock()
	r.servers[c.Subject.CommonName] = c
	return nil
}

func (r *ram) DeleteICA(cn string) error {
	r.Lock()
	defer r.Unlock()
	c, ok := r.ica[cn]
	if !ok {
		return ErrNotFound
	}

	key := fmt.Sprintf("%x", c.SubjectKeyId)
	r.revoked[key] = revoked{c, r.clock.Now()}
	delete(r.ica, cn)
	return nil
}

func (r *ram) DeleteClientCert(cn string) error {
	r.Lock()
	defer r.Unlock()
	c, ok := r.clients[cn]
	if !ok {
		return ErrNotFound
	}

	key := fmt.Sprintf("%x", c.SubjectKeyId)
	r.revoked[key] = revoked{c, r.clock.Now()}
	delete(r.clients, cn)
	return nil
}

func (r *ram) DeleteServerCert(cn string) error {
	r.Lock()
	defer r.Unlock()
	c, ok := r.servers[cn]
	if !ok {
		return ErrNotFound
	}

	key := fmt.Sprintf("%x", c.SubjectKeyId)
	r.revoked[key] = revoked{c, r.clock.Now()}
	delete(r.servers, cn)
	return nil
}

func (r *ram) FindRevoked(skid []byte) (time.Time, *Cert, error) {
	r.Lock()
	defer r.Unlock()

	key := fmt.Sprintf("%x", skid)
	rv, ok := r.revoked[key]
	if !ok {
		return time.Time{}, nil, ErrNotFound
	}
	return rv.when, rv.Cert, nil
}

func (r *ram) MapICA(fp func(*Cert) error) error {
	r.Lock()
	defer r.Unlock()
	for _, c := range r.ica {
		fp(c)
	}
	return nil
}

func (r *ram) MapClientCerts(fp func(*Cert) error) error {
	r.Lock()
	defer r.Unlock()
	for _, c := range r.clients {
		fp(c)
	}
	return nil
}

func (r *ram) MapServerCerts(fp func(*Cert) error) error {
	r.Lock()
	defer r.Unlock()
	for _, c := range r.servers {
		fp(c)
	}
	return nil
}

func (r *ram) MapRevoked(fp func(time.Time, *Cert)) error {
	r.Lock()
	defer r.Unlock()
	for _, c := range r.revoked {
		fp(c.when, c.Cert)
	}
	return nil
}

// XXX Fill this
func (r *ram) ExportJSON() (string, error) {
	return "", nil
}

func (r *ram) dump() {
	root := r.root
	fmt.Printf("root-CA: %x %x %s\n", root.SubjectKeyId, root.SerialNumber, root.NotAfter)
	prmap("servers", r.servers)
	prmap("clients", r.clients)
	prmap("ica", r.ica)
	prmap1("revoked", r.revoked)
}

func prmap(pref string, m map[string]*Cert) {
	fmt.Printf("%s\n", pref)
	for k, v := range m {
		fmt.Printf("   %s: %x %x %s\n", k, v.SubjectKeyId, v.SerialNumber, v.NotAfter)
	}
}

func prmap1(pref string, m map[string]revoked) {
	fmt.Printf("%s\n", pref)
	for k, v := range m {
		fmt.Printf("   %s: at %s %s [%x]\n", k, v.when, v.NotAfter, v.SerialNumber)
	}
}

type dummyClock struct {
	t int64
}

func newDummyClock() *dummyClock {
	t := &dummyClock{
		t: time.Now().UTC().Unix(),
	}
	return t
}

func (d *dummyClock) Now() time.Time {
	z := time.Unix(d.t, 0).UTC()
	return z
}

func (d *dummyClock) advanceDay(n int) {
	d.t += int64(n) * 24 * 60 * 60
}

func (d *dummyClock) advanceSec(n int) {
	d.t += int64(n)
}
