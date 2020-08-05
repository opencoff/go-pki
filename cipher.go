// cipher.go - encrypt/decrypt routines for DB data

//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package pki

// Internal details:
// * We use AES-256-GCM for encrypting all data
// * AES key is derived from the db password +
//   random 32 byte salt via kdf.
// * We use hash of the salt as the nonce for AEAD (GCM)
// * We always store salt + encrypted_bytes
// * The first 32 bytes of data we read from the DB is always
//   the salt.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	_Time    uint32 = 1
	_Mem     uint32 = 1 * 1024 * 1024
	_Threads uint8  = 8

	_NonceSize int = 16
)

// Argon2 KDF
func kdf(pwd []byte, salt []byte) []byte {
	// Generate a 32-byte AES-256 key
	return argon2.IDKey(pwd, salt, _Time, _Mem, _Threads, 32)
}

// Expand a strong KDF derived key into a 32 byte cipher key
func expand(out []byte, pwd, salt []byte) []byte {
	rd := hkdf.Expand(sha512.New, pwd, salt)
	rd.Read(out[:])
	return out
}

// entangle an expanded password with a DB key
func (d *db) key(cn string) []byte {
	m := hmac.New(sha256.New, d.pwd)
	m.Write([]byte(cn))
	m.Write(d.salt)
	return m.Sum(nil)
}

func aeadEncrypt(data []byte, key, salt []byte, ad []byte) ([]byte, error) {
	var nonceb [_NonceSize]byte
	var kdfsaltb [sha256.Size]byte
	var aesKey [32]byte

	nonce := randbytes(nonceb[:])

	h := sha256.New()
	h.Write(nonce)
	h.Write(salt)
	kdfsalt := h.Sum(kdfsaltb[:0])

	key = expand(aesKey[:], key, kdfsalt)
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ae, err := cipher.NewGCMWithNonceSize(aes, len(nonce))
	if err != nil {
		return nil, err
	}

	c := ae.Seal(nil, nonce, data, ad)
	c = append(c, nonce...)

	return c, nil
}

func aeadDecrypt(edata []byte, key, salt []byte, ad []byte) ([]byte, error) {
	n := len(edata)
	var kdfsaltb [sha256.Size]byte
	var aesKey [32]byte

	// Max GCM tag size is 16
	// XXX This is not a constant exposed by crypto/aes
	//     we have to instantiate an aead instance to get the tag size! Grr.
	if n < (16 + _NonceSize) {
		return nil, ErrTooSmall
	}

	nonce := edata[n-_NonceSize:]
	edata = edata[:n-_NonceSize]

	h := sha256.New()
	h.Write(nonce)
	h.Write(salt)
	kdfsalt := h.Sum(kdfsaltb[:0])

	key = expand(aesKey[:], key, kdfsalt)
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ae, err := cipher.NewGCMWithNonceSize(aes, len(nonce))
	if err != nil {
		return nil, err
	}

	return ae.Open(nil, nonce, edata, ad)
}

// encrypt a blob and return it
func (d *db) encrypt(b []byte) ([]byte, error) {
	return aeadEncrypt(b, d.pwd, d.salt, d.salt)
}

// decrypt a buffer and return
func (d *db) decrypt(b []byte) ([]byte, error) {
	return aeadDecrypt(b, d.pwd, d.salt, d.salt)
}

// read random bytes and return it
func randbytes(b []byte) []byte {
	n, err := rand.Read(b)
	if err != nil || n != len(b) {
		panic(fmt.Sprintf("rand read %d fail (%s)", len(b), err))
	}

	return b
}
