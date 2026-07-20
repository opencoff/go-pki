# Security Analysis: go-pki

Analysis of the `go-pki` library as of commit `abcba50`, done in preparation for a
cleanup/refactor (store abstraction, known-root initialization, ergonomic issuance).
Findings are ordered by severity. Items marked **[confirmed]** were reproduced with
throwaway tests against the current code.

Architecture recap: a single `CA` type wraps an x509 cert + ECDSA key; storage goes
through the `Storage` interface, implemented by a boltdb backend. All records are
AEAD-encrypted (AES-256-GCM) under a random 32-byte DB master key, which is itself
encrypted under an Argon2id-derived KEK from the user passphrase. Private keys are
PEM blobs inside the record; client/server keys may additionally be passphrase
encrypted with legacy PEM (RFC 1423) encryption.

---

## High severity

### H1. `ExportJSON` dumps the DB master key and all private keys in plaintext
`jsonv1.go:112-125` — the export blob contains:

- `Rawkey: d.pwd` — the **DB master key** itself,
- `Salt: d.salt`,
- root CA private key as **unencrypted PEM** (root/ICA keys are stored as plaintext
  PEM inside the AEAD envelope; export strips the envelope),
- all client/server private keys (plaintext PEM unless a per-cert passphrase was
  supplied at issuance).

The master key is only consumed by the v0-compat path of the importer
(`parseJsonv1RootCertKey`), which uses `hex(Rawkey)` as a PEM decryption password.
For v1 exports the key is leaked gratuitously. Anyone who obtains an export file
owns the entire PKI; nothing in the API name (`ExportJSON`) or docs signals this.

*Fix direction:* export should be encrypted (e.g. re-use the AEAD under a
user-supplied export passphrase), and must never include the DB master key.

### H2. Wrong password + JSON import silently corrupts the DB (error shadowing) [confirmed]
`boltdb.go:246-253`:

```go
err = bdb.Update(func(tx *bolt.Tx) error { ... })   // password verified here
if len(dbc.Json) > 0 {
        err = d.importJson(dbc.Json)                 // <-- overwrites err
}
return d, err
```

If the DB exists and the passphrase is wrong, the `Update` closure fails with
"wrong password?" — but when a JSON payload is present (the `NewFromJSON` path),
that error is overwritten. The import then proceeds with `d.pwd == nil` and a
zeroed `d.salt`, writing records "encrypted" under an empty key into the existing
DB (overwriting the root CA record), and **returns success**. Reproduced: opening
an existing DB with a wrong password + JSON returns `err == nil`.

*Fix:* `if err != nil { return d, err }` before the import; also make
`NewFromJSON` refuse to import into a pre-populated DB.

### H3. Per-cert key encryption uses broken legacy PEM (RFC 1423) crypto
`cert.go:977-1010` uses `x509.EncryptPEMBlock` / `DecryptPEMBlock` /
`IsEncryptedPEMBlock` (also `jsonv1.go:330,371`). These are deprecated in Go with
the note that the mechanism is *insecure by design*: MD5-based single-iteration
key derivation and unauthenticated CBC. The user-supplied per-cert passphrase —
the only protection a client key retains once exported (H1) — is therefore
trivially brute-forceable offline.

*Fix:* wrap keys with the same Argon2id + AEAD construction used elsewhere in the
DB (or age/scrypt-style envelope), not RFC 1423 PEM.

### H4. Private-key passphrase leaked into error strings
`cert.go:981`:

```go
return fmt.Errorf("can't decrypt private key (pw=%s): %s", pw, err)
```

A wrong (or right-but-mismatched) passphrase is echoed verbatim into an error
that callers will log.

---

## Medium severity

### M1. JSON import writes the serial under the wrong key — imported serial is lost [confirmed]
The importer stores the serial under the HMAC'd key `d.key("serial")`
(`jsonv1.go:290`), but creation and every read/write elsewhere use the raw key
`[]byte("serial")` (`boltdb.go:157,167,768`). The carefully computed
max-serial from the import is therefore invisible after reopen; the DB continues
from the random serial generated at creation time. Reproduced: serial after
reopen differs from the imported serial. This defeats the importer's own
"don't blindly trust the incoming serial#" logic; duplicate serials under the
same issuer DN become possible (probability bounded by the 120-bit random start,
but the invariant is broken).

### M2. JSON import writes revoked entries in the wrong format — CRL/lookups break [confirmed]
`jsonv1.go:245-247` stores `revokedgob.Cert = []byte(r.Cert)` (raw **PEM**), but
every reader (`MapRevoked`, `FindRevoked`, boltdb.go:478,522) expects a
**gob-encoded `certgob`**. After importing a dump that contains any revoked cert,
`MapRevoked` fails (`can't decode gob`), which breaks `ListRevoked`, CRL
generation, `IsRevokedCA`, and (via the revocation check) `Find*`. Reproduced.

### M3. `SignCert` is an unauthenticated, unconstrained signing oracle
`cert.go:217-274` takes a caller-supplied `*x509.Certificate` template and signs
it with only these adjustments: serial, SKID-if-missing, `IsCA` rejection,
basic-constraints flags. Consequences:

- **No proof-of-possession**: it accepts an `x509.Certificate`, not a
  `x509.CertificateRequest`, so no CSR signature is ever verified. Any public key
  can be certified.
- **No validity clamping**: `NotBefore`/`NotAfter` are taken as-is; a zero-valued
  template yields nonsense validity; nothing prevents validity beyond the CA's own.
- **Caller-controlled extensions pass through**: `KeyUsage`, `ExtKeyUsage`,
  `ExtraExtensions`, SANs are signed verbatim. A template with
  `KeyUsageCertSign` (and `IsCA=false`) still gets signed.
- Certs with no EKU are classified (and stored) as **server** certs by default.
- `MaxPathLenZero=true` together with `MaxPathLen=-1` is contradictory (harmless
  for non-CA certs, but shows the template is not normalized).

For the planned "ergonomic issuance" refactor this whole path should be replaced
by CSR-based issuance with an explicit, whitelisted profile.

### M4. No issuance-time validity validation anywhere
`newCert` (cert.go:853) and `NewIntermediateCA` (cert.go:583) accept any
`ci.Validity`: negative durations silently produce `NotAfter < NotBefore`;
child certs and ICAs may outlive their issuer (only root creation checks
`exp.Before(now)`). Certs that expire after their issuer will fail at use time in
any correct verifier.

### M5. CN-keyed storage: re-issuing a CN silently orphans a live cert
Certs are keyed by `Subject.CommonName` (`storeCert`, boltdb.go:594). Issuing a
second cert with the same CN **overwrites** the record; the first cert remains
cryptographically valid but is no longer tracked — it can never be found, revoked,
or listed in a CRL. Similarly, the revoked bucket is keyed by
`SubjectKeyId = SHA256(pubkey)`, so re-certifying the same key pair collides with
its own revocation record (`IsRevokedCA` will report the new cert's CA as revoked).
Issuance should refuse duplicate CNs (or key by serial and revoke-on-replace).

### M6. Encrypted records are not context-bound; no rollback protection
`d.encrypt`/`d.decrypt` (cipher.go:127-134) use the same AD (`d.salt`) for every
record in the DB. Any ciphertext decrypts correctly at any location: an attacker
with write access to the bolt file can copy a record from the `client` bucket into
the `server` bucket (turning a client cert into a "server" cert), resurrect a
revoked/deleted record verbatim, or roll back individual records to older values.
The AEAD should bind bucket name + record key (CN) in the AD, and ideally a
generation counter for freshness.

### M7. Nil-pointer panics on malformed input [confirmed]
`Cert.decryptKey` (cert.go:972-974) does `blk, _ := pem.Decode(key)` and then
dereferences `blk` unchecked. Reproduced: fetching a cert that has no stored key
(exactly what `SignCert` stores — `Key == nil`, `Rawkey == nil`) with a non-empty
password panics. The same unchecked `pem.Decode` pattern exists in
`parseJsonv1RootCertKey` (jsonv1.go:328), `parseJsonv1CertKey` (jsonv1.go:359,370)
and `storeRevoked` (jsonv1.go:238), so a malformed/hostile JSON dump panics the
importer instead of returning an error.

### M8. CRL model is wrong and built on deprecated APIs
`crl()` (cert.go:789-809) signs a single global revocation list with whichever CA
instance the method is called on — revoked certs issued by *other* CAs appear in
a CRL signed by a non-issuer, which conforming verifiers must ignore. It also uses
the deprecated `Certificate.CreateCRL` (produces a v1 TBSCertList without
CRLNumber/AKI extensions — RFC 5280 §5 requires these for v2 CRLs; some verifiers
reject) and `GetAllRevoked` uses deprecated `pkix.CertificateList`/`ParseDERCRL`.
Should move to `x509.CreateRevocationList` with per-issuer CRLs.

### M9. JSON import trusts its input completely
Beyond M2/M7: imported certs and ICAs are never verified to chain to the imported
root; no signature checks at all. A crafted dump can inject arbitrary "trusted"
ICAs (with attacker-known keys) into the store. The import path is also where the
AKI-cycle DoS (L4) becomes reachable. If import is meant only for operator-supplied
backups this is a trust decision, but for an embeddable library it needs at least
chain verification and structural validation.

---

## Low severity / robustness

- **L1. Leaked bolt handle on error**: `New`/`NewFromJSON` (cert.go:108-137)
  discard the `Storage` without `Close()` when `newWithClock`/import fails; bbolt
  holds an exclusive flock with no timeout, so a later open in the same process
  blocks forever. (`openBoltDB` deliberately returns `d, err` non-nil precisely so
  it can be closed — the callers don't.)
- **L2. Revocation checks soft-fail open**: `isRevokedCA` returns `(false, err)`
  on storage errors and callers use `if err == nil && ok` (cert.go:331,383,397) —
  a DB error is treated as "not revoked". For a PKI, fail-closed is safer.
- **L3. Expired ICAs are misreported as revoked**: `findCAs` (cert.go:753-770)
  silently skips expired ICAs, so their descendants get `CARevoked = true` /
  `ErrCARevoked` instead of an expiry error.
- **L4. `isRevoked` can loop forever** (cert.go:679-691) if AKI references form a
  cycle (constructible via JSON import).
- **L5. `Chain()` on the root CA returns the root twice** (cert.go:488-505: the
  root is appended once via the SKID lookup and again via the AKID walk).
- **L6. Argon2 parameters hardcoded and heavy**: time=1, **1 GiB** memory,
  threads=8 (cipher.go:35-37). Every DB open (and rekey) allocates ~1 GiB —
  hostile to embedded/containerized deployments; should be configurable with sane
  defaults (e.g. RFC 9106 second recommendation: 64 MiB, t=3).
- **L7. Sequential serials** from a random start. Fine for a closed PKI, but note
  CA/Browser-forum-style policy wants ≥64 bits of per-cert CSPRNG output.
- **L8. Key material hygiene**: `db.Close` zeroes the master key, but `CA.key`,
  decrypted cert keys, the Argon2 KEK, and derived AES keys are never wiped;
  `CA.Close` only nils pointers. (Best-effort in Go, but currently inconsistent.)
- **L9. `os.Stat`-then-open TOCTOU** in `openBoltDB`; `fi, _ := os.Stat` swallows
  errors (e.g. EACCES misreported as "will create"); `path.Dir` used instead of
  `filepath.Dir`.
- **L10. Library prints to stdout** on import errors (jsonv1.go:146,203,214,222).
- **L11. Empty passphrase accepted silently** for the DB master key (all tests use
  `Passwd: ""`); no minimum-strength policy or warning.
- **L12. `_MinValidity` surprise**: everything is treated as expired 24h *before*
  actual `NotAfter` — including the root at open time (`newWithClock`,
  cert.go:174), so a DB whose CA expires within a day cannot even be opened to
  export or rotate it.

## Informational / cosmetic

- vet: unreachable code at boltdb.go:806; `db.initialized` is never used.
- Stale/wrong comments: cipher.go's header describes a "hash of the salt as
  nonce" scheme that is not what the code does (the code is *better*: random
  nonce + per-record HKDF key); error strings say "P256" where P-521 is used
  (cert.go:565,913); `newCert`'s server branch comment says "nsCert = Client";
  README says client keys are "Secp256k1" (they are P-256/secp256r1, a very
  different curve).
- `x509.Certificate.Issuer` is set in templates but ignored by
  `x509.CreateCertificate`.
- `elliptic.Marshal` (boltdb.go:779) is deprecated.
- ECDSA-with-SHA512 is forced even for P-256 leaf keys — valid but unconventional
  (P-256 pairs with SHA-256); some stacks special-case the conventional pairs.
- `Cert.PEM()` returns whatever `Rawkey` happens to hold: encrypted PEM, plaintext
  PEM, or nil depending on how the cert was obtained — inconsistent contract.
- Freshly issued certs have `Rawkey == nil` (marshalCert never writes it back), so
  `ck.PEM()` on a just-issued cert returns a nil key; callers must re-fetch.

## What the crypto gets right

Worth preserving through the refactor: AEAD (AES-256-GCM) over every record with a
fresh random nonce *and* a per-record HKDF-derived key (nonce collision is a
non-issue); Argon2id as the passphrase KDF; HMAC-derived bucket keys that hide CNs
from casual inspection of the DB file; randomized starting serial; SKID computed as
SHA-256 of the SPKI (RFC 7093-style); root created with pathlen unset and conscious
pathlen propagation for ICAs.

## Implications for the planned refactor

1. The `Storage` interface currently traffics in passphrases (`GetClientCert(nm,
   pw)`) and half-encrypted `Cert` objects (`Rawkey` vs `Key`). Key
   encryption/decryption should move above the storage layer so stores only ever
   see opaque sealed blobs — that fixes H3/H4 structurally and makes alternate
   stores (files, KMS, SQL) trivial.
2. "Initialize with a known signing root + CA cert" needs a supported import path;
   today's JSON import (H1, H2, M1, M2, M7, M9) is the weakest part of the code —
   replace it rather than extend it.
3. Ergonomic issuance should be profile-based (server/client/ICA profiles with
   clamped validity, fixed KU/EKU, duplicate-CN policy) and CSR-based for external
   keys, replacing `SignCert` (M3).
