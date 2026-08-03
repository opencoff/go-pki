# go-pki: Regime Design

Status: draft for review
Target: replacement for the current `pki` package

---

## 1. Purpose

A PKI library for **closed environments**, embeddable in other projects, with two
deployment shapes:

1. A **self-anchored regime** — a self-signed root of trust that issues an
   arbitrary but *bounded* hierarchy of CAs terminating in leaf CAs that issue
   end-entity certificates.
2. A **tenant-anchored regime** — the same, plus a cryptographic attestation
   from a tenant's existing PKI that the regime's root of trust is approved.

Everything is `crypto/x509` plus policy. **No non-stdlib dependencies.**

### Goals

- Issue and revoke X.509 certificates from a hierarchy whose shape is fixed and
  enforced, both locally and by conforming third-party verifiers.
- Consume CSRs and return signed certificates under an explicit profile.
- Support an externally attested root of trust without requiring the tenant to
  grant a subordinate CA.
- Keep private keys sealed at rest; support HSM/KMS custody at any node.
- Make the hot path (certificate issuance) independent of storage.

### Non-goals

- Public-web PKI. No CT, no CAA, no ACME.
- Post-quantum or SHA3 *signatures* — not reachable via stdlib (§7).
- Being a certificate transparency log, an OCSP responder, or a TLS stack.

---

## 2. Architecture

Two layers, dependency pointing one way.

```
   ┌─────────────────────────────────────────────┐
   │ Regime          control plane               │
   │   hierarchy, Store, seed, anchor, ceremonies │
   │   rare; provisioning path                    │
   └────────────────────┬────────────────────────┘
                        │ LeafCA.Issuer()
   ┌────────────────────▼────────────────────────┐
   │ Issuer          data plane                  │
   │   stateless CSR signing; no Store, no seed   │
   │   frequent; hot path                         │
   └─────────────────────────────────────────────┘
```

An issuing service needs only a leaf-CA key, its chain, and a policy. It does
not need a Store, a seed, or knowledge that a Regime exists. This is what lets
the root live offline while issuance runs continuously.

---

## 3. Vocabulary

| Term | Meaning |
|---|---|
| **rootCert / RootCA** | Self-signed. The operational root of trust; progenitor of every certificate in the regime. ~10-year span. |
| **Intermediate** | A CA between the root and a leaf CA. May issue further CAs. |
| **LeafCA** | Terminal CA. Issues end-entity certificates only. `pathlen 0`. |
| **Issuer** | Stateless signing façade produced by a LeafCA. |
| **anchorCert** | A tenant-signed **end-entity** certificate carrying `hash(rootCert)`. Not in any signing path. |
| **RoT_Hash** | `SHA-256(rootCert.Raw)`. Embedded in anchorCert by the tenant CA. |
| **AnchorHash** | `SHA-256(anchorCert.Raw)`. Embedded in every certificate the regime issues. |
| **Depth (D)** | Number of CA levels, rootCert..LeafCA inclusive. Fixed at creation. `D >= 2`. |
| **Bundle** | Shippable set: leaf, its chain to rootCert, anchorCert, its chain to the tenant root. |

---

## 4. Trust model

### 4.1 Two disjoint trees, joined by a staple

The regime's tree and the tenant's tree share **no certification path**. They are
joined by a pair of hash references:

```
  Tenant Root CA                         rootCert  (self-signed)
       │ signs                                │ signs
       ▼                                      ▼
  anchorCert  ◄── RoT_Hash ──────────────  Intermediate…
  (CA:FALSE)                                  │
       ▲                                      ▼
       └────────── AnchorHash ───────────  LeafCA
                                              │
                                              ▼
                                            leaf
```

- The tenant signs a statement containing `hash(rootCert)`. Only the tenant can
  produce it. **This is the approval.**
- Every certificate the regime issues carries `hash(anchorCert)`, naming which
  attestation it was minted under.

### 4.2 Why anchorCert is CA:FALSE

This is the load-bearing decision of the whole design. Because anchorCert is an
ordinary end-entity certificate outside the signing path:

- **No subject DN preservation is required.** The tenant may rewrite it freely.
- **No pathLenConstraint negotiation is required.**
- **No subordinate-CA grant is required** — you ask for an ordinary certificate,
  the most routine operation an enterprise PKI performs.

Measured (`crypto/x509`, Go 1.26): under a cross-certification design, a tenant
adding a single `OU=` to the subject DN, or issuing with `pathlen=0` — both
common defaults — breaks the entire hierarchy:

```
tenant preserves subject DN exactly       -> chains OK
tenant rewrites O= in the subject DN      -> BROKEN: signed by unknown authority
tenant appends an OU= to the subject DN   -> BROKEN: signed by unknown authority
tenant preserves DN but forces pathlen=0  -> BROKEN: too many intermediates
```

The staple design sidesteps all of it. Getting a subordinate CA from a corporate
PKI is a quarters-long political project; getting a leaf certificate is a ticket.

### 4.3 Verification: six steps, and step 6 is mandatory

```
1. leaf -> … -> rootCert                      (regime tree, standard X.509)
2. read AnchorHash from the leaf
3. hash(bundle.Anchor) == AnchorHash
4. anchorCert -> tenant root, + revocation    (tenant tree, standard X.509)
5. read RoT_Hash from anchorCert
6. BACK-CHECK: RoT_Hash == hash(rootCert)
```

Step 6 is what resists forgery. `AnchorHash` is public and freely copyable — an
attacker can staple it into their own hierarchy. What they cannot do is make the
tenant's attestation name *their* root. Measured:

```
legitimate leaf              -> TENANT-ATTESTED
forged leaf (stolen hash)    -> rejected: step6 BACK-CHECK FAILED
tenant CA stripped our ext   -> rejected: step5: no root attestation
```

**A verifier that reads the marker and skips step 6 is strictly worse than one
that ignores the marker entirely**, because it reports a trust property it never
checked. The API therefore exposes no accessor that returns an attestation
conclusion without having performed the back-check.

### 4.4 Transitive trust — the payoff

A relying party may establish trust two ways:

- **`RootPin`** — it already trusts this regime's root. Standard chain
  validation; the staple is not consulted.
- **`TenantRoots`** — it has *never heard of this regime*. Trust arrives
  transitively: the anchor attests `hash(rootCert)` and chains to a tenant root
  the relying party does trust.

The second mode is the reason the architecture exists. A workload configured
only with the corporate root can accept certificates from a regime it was never
told about.

### 4.5 What this does NOT give you

Stated plainly because it reads like a property of the certificate when it is a
property of the verifier:

- **Stock verifiers see nothing.** The marker is a non-critical extension, so
  openssl, curl, browsers, and every sidecar you did not ship ignore it. Marking
  it critical is not an option — unrecognized critical extensions cause outright
  rejection. Measured: a forged leaf validates perfectly against its own root
  under stock X.509 and is indistinguishable without step 6.
- **The floor is not enforceable.** `pathLenConstraint` is a *maximum*; X.509 has
  no minimum-depth mechanism. "Intermediates must be present before a leaf CA"
  is enforced by this library and by key custody, not by any verifier.
- **A one-clause dependency on the tenant.** If the tenant's CA strips the
  extension, the design yields nothing. See §12.

---

## 5. Hierarchy and the pathlen ladder

`Depth D` is frozen at creation and recorded in the Store. `D >= 2`: at `D == 1`
the root would issue end-entity certificates directly, defeating the invariant
and forcing `Root` to grow an `Issuer()` method.

For a CA at level *i* (root = 1, LeafCA = D):

```
pathLenConstraint(level i) = D - i     root = D-1  …  LeafCA = 0
```

Capability separation is expressed in the type system and mirrored
cryptographically, so external verifiers agree with the Go types:

| Type | Levels | May create | pathlen |
|---|---|---|---|
| `Root` | 1 | Intermediate, LeafCA | `D-1` |
| `Intermediate` | 2..D-1 | Intermediate, LeafCA | `D-i` |
| `LeafCA` | D | *nothing* — terminal | `0` |

`LeafCA` has no `NewIntermediate`/`NewLeafCA`, so terminality is a compile error;
`pathlen 0` makes it a validation error everywhere else. Measured: a
`pathlen=0` CA that signs a sub-CA is rejected with `x509: too many
intermediates for path length constraint`.

### 5.1 Two implementation traps

**`MaxPathLenZero`.** Measured behaviour of `x509.CreateCertificate`:

| Template | Emitted |
|---|---|
| `MaxPathLen: 0, MaxPathLenZero: true` | `pathLenConstraint = 0` ✓ |
| `MaxPathLen: 0, MaxPathLenZero: false` | **ABSENT — unconstrained CA** |
| `MaxPathLen: -1, MaxPathLenZero: true` | ABSENT |

Writing the obvious `MaxPathLen: 0` for a leaf CA silently produces an
**unconstrained** CA. Every leaf CA depends on this, so it goes behind one
constructor that sets both fields from a single integer and is never open-coded.

**Trust-anchor pathlen is not portable.** Strict RFC 5280 §6.1 takes the trust
anchor as a (name, key) pair and never processes its basicConstraints, but Go
enforces it — `verify.go:496` is not gated on certificate type, and
`root(pathlen=1) → ica1 → ica2 → leaf` is rejected. Do not rely on it: always
emit the full decreasing ladder on every certificate issued, since those are
unambiguously intermediates and are honoured everywhere.

**Self-issued certificates.** RFC 5280 counts only *non-self-issued*
intermediates; Go's check is `len(currentChain) - 1` with no such filtering, so
Go is stricter. Budget one level of headroom if key rollover via self-issued
certificates is in your future.

---

## 6. Validity ladder and clamping

| | Validity | pathlen |
|---|---|---|
| rootCert | ~10y | `D-1` |
| Intermediate | ~3y | `D-i` |
| LeafCA | ~1y | `0` |
| leaf | days–90d | — |
| anchorCert | tenant's choice, 1–2y | n/a (CA:FALSE) |

Every certificate is clamped to its issuer's `NotAfter`. Leaves are additionally
clamped to `anchorCert.NotAfter`.

**That second clamp designs the anchor-expiry problem out of existence.** Any
leaf still valid necessarily references an anchor still inside its validity
window, so the verifier needs no fall-forward logic and no historical-anchor set.
The only runtime check left at step 4 is *revocation*.

Clamping is never silent: issuance returns `EffectiveNotAfter`.

A 10-year root has two consequences worth planning for: the **suite is frozen for
a decade**, so root rotation must be a supported ceremony rather than an
emergency; and the root key must be protected for ten years, which is why the
cold-root property (§9.4) is the default rather than a discipline.

---

## 7. Suites

A `Suite` pins algorithms by slot, is frozen at creation, recorded in the Store,
and **re-validated against every certificate at open**. Validating only at
issuance would let anyone with Store write access downgrade the regime.

### 7.1 What is actually reachable

Verified against the Go 1.26 toolchain:

- `x509.SignatureAlgorithm` contains **no SHA3 and no ML-DSA** variants. The
  complete set is RSA/RSA-PSS with SHA-256/384/512, ECDSA with SHA-256/384/512,
  and PureEd25519.
- ML-DSA exists only at `crypto/internal/fips140/mldsa` — internal, unexported,
  not reachable from `x509`. There is no public `crypto/mldsa`.
- `crypto/mlkem` is public but is a **KEM**, not a signature scheme. Useless for
  certificates.

A PQC or SHA3 *signature* suite is therefore not implementable on stdlib today,
and the IETF composite/hybrid drafts are still moving — committing an on-disk
format to them now would be a durable mistake for certificates that live years.

SHA3 *is* used internally for the seal KDF (§8), where no interop constraint
applies.

### 7.2 FIPS

`crypto/fips140.Enabled()` reports FIPS 140-3 mode, controlled by
`GODEBUG=fips140=on|only` and pinned via `GOFIPS140`. This is a **build/runtime
property, not a suite property** — a suite cannot make you compliant, only avoid
disqualifying you. `SuiteV1FIPS` therefore *asserts*: construction fails if
`fips140.Enabled()` is false, surfacing the mismatch at startup rather than at
audit.

### 7.3 Shipped suites

| | CA key | Leaf key | Hash | Accepted from CSR |
|---|---|---|---|---|
| `SuiteV1` | P-384 | P-256 | SHA-2 | P-256, P-384, Ed25519 |
| `SuiteV1FIPS` | P-384 | P-256 | SHA-2 | P-256, P-384, RSA-3072 |

Suite names are reserved so a future `SuiteV2Hybrid` is a data change, not a
refactor.

---

## 8. Storage and sealing

### 8.1 Three orthogonal concerns

| Concern | Interface | Backends |
|---|---|---|
| Where bytes live | `Store` | files, S3, etcd, SQL, Consul |
| How the seed is protected | `SeedGuard` | Argon2id passphrase, KMS envelope, TPM |
| How signing happens | `crypto.Signer` | in-process, PKCS#11, KMS, TPM |

Custody is **per node, not per level**: the root may be HSM-resident while leaf
CAs are sealed blobs.

### 8.2 Store

```go
type Store interface {
	Get(key string) ([]byte, error)
	Put(key string, val []byte) error
	Delete(key string) error
	List(prefix string) ([]string, error)

	// CAS updates key only if its current value matches old. Required for
	// monotonic CRL numbers when more than one process writes.
	CAS(key string, old, new []byte) error
}
```

A dumb key/value store of opaque blobs. It never sees plaintext key material and
never takes a passphrase. Records are keyed by **path or SKID, never by CN** —
CN-keyed storage silently orphans a live, unrevocable certificate when a CN is
re-issued.

### 8.3 Sealing

The Regime generates a **64-byte root seed** at creation. Every secret is sealed
with a key and nonce derived from that seed:

```
version = 1
salt    = randbytes(16)
prk     = HKDF-SHA3-512(seed, salt=salt, info=context, len=44)
key     = prk[:32]
nonce   = prk[32:44]
blob    = version || salt || AES-256-GCM(key, nonce, plaintext, aad=version)
```

Overhead is 33 bytes per record.

**Why this beats plain random-nonce GCM.** Because the key is re-derived per
operation, nonce reuse requires a 128-bit salt collision rather than the 96-bit
nonce birthday bound. NIST's ~2³² invocations-per-key ceiling for GCM does not
apply.

**Context binding.** `info` carries the record's full identity:

```
ternstack/v1/ca-key/<path>
ternstack/v1/crl-state/<path>
ternstack/v1/anchor
```

This closes the M6 finding from the security audit of the old code, which used
identical associated data for every record and therefore allowed an attacker with
Store write access to relocate a blob between buckets and have it decrypt
happily. Measured:

```
same store, sibling CA slot  -> REJECTED: cipher: message authentication failed
relocated to a CRL record    -> REJECTED: cipher: message authentication failed
flipped a ciphertext bit     -> REJECTED: cipher: message authentication failed
flipped a salt bit           -> REJECTED: cipher: message authentication failed
bumped the version byte      -> REJECTED: unknown seal version 2
```

A misfiled blob now fails at key derivation, not merely at tag check.

**Versioning.** The version byte is authenticated as GCM AAD, so a format
downgrade is detected rather than parsed as v1.

### 8.4 SeedGuard

```go
// SeedGuard protects the regime's 64-byte root seed at rest. Called once on
// open, never per record. The Regime never exposes the seed.
type SeedGuard interface {
	Protect(seed []byte) ([]byte, error)
	Recover(protected []byte) ([]byte, error)
}
```

Because the Regime owns the seed, the injectable contract shrinks from a
general-purpose sealer invoked once per key to a **single-item guard invoked once
at open**: one KMS round-trip per process rather than one per key, and all
per-record crypto becomes local, fast, and deterministically testable.

Two KMS-backed guards, deliberately distinguished:

- `NewSecretStoreGuard` — the seed is fetched verbatim. The portable
  least-common-denominator across platforms.
- `NewKMSGuard` — envelope encryption; the seed never leaves the KMS unwrapped.
  Costs a round-trip but gives the tenant an **access log and a revocation
  lever**, the same kill-switch property the anchor provides.

### 8.5 Two distinct rotation operations

The old code conflated these — its `Rekey()` re-encrypted the KEK while claiming
to rekey the database.

```go
func (r *Regime) ReprotectSeed(g SeedGuard) error // O(1): passphrase/KMS change
func (r *Regime) RotateSeed() error               // O(n): re-seals every key
```

---

## 9. Lifecycle

### 9.1 Self-anchored

```go
func NewRegime(cfg *Config, st Store, g SeedGuard) (*Regime, error)
```

Generates the seed, generates `rootKey`, self-signs `rootCert` with
`pathlen = D-1`. Issued certificates carry no `AnchorHash`.

### 9.2 Tenant-anchored — a ceremony, not a constructor

```go
func NewRegimeBuilder(cfg *Config, st Store, g SeedGuard,
	anchorKey KeySource) (*RegimeBuilder, []byte, error)

func ResumeRegimeBuilder(st Store, g SeedGuard) (*RegimeBuilder, error)

func (rb *RegimeBuilder) AnchorCSR() []byte
func (rb *RegimeBuilder) RootHash() []byte
func (rb *RegimeBuilder) Install(anchorCert []byte, caChain [][]byte) (*Regime, error)
func (rb *RegimeBuilder) Discard() error
```

The builder generates `rootKey`, self-signs `rootCert`, and produces an
`anchorCSR` carrying `hash(rootCert.Raw)` under the regime OID. `anchorKey` is a
separate key whose only purpose is CSR proof-of-possession; it typically lives in
an HSM/KMS and signs nothing else.

**Both keys are sealed to the Store immediately.** The tenant round-trip runs on
ticket-queue time; a process restart must not destroy an approval that took weeks
to obtain. Hence `ResumeRegimeBuilder`.

**Nothing can be issued before `Install`** — every issued certificate embeds
`hash(anchorCert)`, so the anchor must exist first. The builder state is not
optional ceremony; it is a data dependency.

`Install` validates, with a distinct error for each:

1. `anchorCert.PublicKey` matches **`anchorKey`** (not `rootKey`)
2. the regime OID is present and `RootHash == hash(rootCert.Raw)` →
   `ErrAttestationStripped`
3. `caChain` verifies `anchorCert` to a self-signed root
4. `anchorCert` is not revoked

Deliberately **not** required: subject DN preservation, `pathLenConstraint`,
`CA:TRUE`. See §4.2.

### 9.3 Opening

```go
func OpenRegime(st Store, g SeedGuard, pin RootPin) (*Regime, error)
```

`pin` supplies the expected root identity **out of band**. Everything else is
validated against it; reading the anchor of trust from the Store would make Store
write access a total compromise. Open also re-validates suite conformance and the
pathlen ladder across every loaded certificate.

There is no `create bool`. A boolean that switches between "read this" and
"initialize this" is a latent data-loss bug — in the old code it is precisely
what allowed a wrong password to silently overwrite a live root CA.

### 9.4 Cold root

```go
func (r *Regime) SealRoot() error
```

In the anchored model the root signs exactly twice — self-signing `rootCert`, and
signing the top of the hierarchy. Over a 10-year span it should be cold by
default, not by discipline.

### 9.5 Re-anchoring

```go
func (r *Regime) Anchor() *Anchor
func (r *Regime) AnchorExpiresIn() time.Duration
func (r *Regime) Reanchor() (*RegimeBuilder, error)
```

Anchors form a **series over one stable root**: anchor₁, anchor₂, … each carrying
the identical `RoT_Hash`, each independently sufficient for the back-check. New
leaves bind to the current anchor; leaf clamping (§6) means older leaves expire
before their anchor does.

**Tenant-facing semantics that must be in the runbook:** revoking one anchorCert
does **not** withdraw approval of the regime. It kills exactly the leaves issued
in that epoch — useful epoch-granular revocation — but full withdrawal means
*revoke every outstanding anchor and decline to issue new ones*. Keep renewal
overlap short (days, not months) to bound how many anchors a tenant must track.

---

## 10. API sketch

### 10.1 Suite, policy, profiles

```go
type Suite struct {
	Name      string
	CAKey     KeyAlgorithm
	LeafKey   KeyAlgorithm
	Hash      crypto.Hash
	AcceptCSR []KeyAlgorithm
}

func (s Suite) Validate() error
func (s Suite) Conforms(c *x509.Certificate) error

type Profile uint8

const (
	ProfileServer       Profile = iota // DigitalSignature + ServerAuth
	ProfileClient                      // DigitalSignature + ClientAuth
	ProfileSigning                     // DigitalSignature + ContentCommitment
	ProfileKeyAgreement                // KeyAgreement (ECDH)
)

// Policy is enforced locally at issuance. Only pathlen, name constraints and
// EKU travel in the certificate; everything else here is invisible afterward.
type Policy struct {
	MaxValidity     time.Duration
	Profiles        []Profile
	NameConstraints *NameConstraints
	Backdate        time.Duration // clock skew, ~5m
}
```

`KeyEncipherment` is never set on an ECDSA certificate; it is meaningless there
and its presence in the old code is a copy-forward mistake. `nsCertType` is
dropped entirely.

### 10.2 Issuer

```go
func NewIssuer(cert *x509.Certificate, key crypto.Signer,
	chain []*x509.Certificate, pol Policy, opts ...IssuerOption) (*Issuer, error)

func WithProvenance(p Provenance) IssuerOption

type Request struct {
	CSR      []byte // PEM or DER; signature always checked (proof of possession)
	Profile  Profile
	Validity time.Duration
}

type Issued struct {
	Cert              *x509.Certificate
	Chain             []*x509.Certificate
	EffectiveNotAfter time.Time // after clamping; may be earlier than requested
}

func (i *Issuer) Sign(r Request) (*Issued, error)
func (i *Issuer) IssueLocal(subj pkix.Name, sans SANs, p Profile,
	v time.Duration) (*Issued, crypto.Signer, error)
func (i *Issuer) SignCRL(entries []x509.RevocationListEntry,
	number *big.Int, validFor time.Duration) ([]byte, error)
```

Subject and SANs are taken from the CSR and filtered by policy. KU, EKU,
BasicConstraints, serial and SKID always come from the profile. **CSR extensions
are never copied through** — Go does not do this automatically, and the copying
site is where a whitelist belongs.

Serials are 128 bits from `crypto/rand`. No counter, no persisted state.

### 10.3 Hierarchy

```go
type Authority interface {
	Cert() *x509.Certificate
	Chain() []*x509.Certificate
	Parent() Authority // nil at the root
	Level() int        // root == 1
}

type node struct{ /* recursion lives here; parent == nil terminates */ }

type Root struct{ node }
type Intermediate struct{ node }
type LeafCA struct{ node }

type CASpec struct {
	Subject         pkix.Name
	Validity        time.Duration // clamped to parent NotAfter
	NameConstraints *NameConstraints
	Key             KeySource
	Policy          Policy
}

func (r *Root) NewIntermediate(s CASpec) (*Intermediate, error)
func (r *Root) NewLeafCA(s CASpec) (*LeafCA, error)
func (i *Intermediate) NewIntermediate(s CASpec) (*Intermediate, error)
func (i *Intermediate) NewLeafCA(s CASpec) (*LeafCA, error)

func (l *LeafCA) Issuer() (*Issuer, error)
func (l *LeafCA) Revoke(serial *big.Int, reason int, at time.Time) error
func (l *LeafCA) CRL(validFor time.Duration) ([]byte, error)
```

Revocation is **per issuer**. A CRL signed by a non-issuer must be ignored by
conforming verifiers; the old code signed one global list with whichever CA
happened to be in hand. Each authority keeps its own set and monotonic CRL
number, which is what `Store.CAS` exists for.

Name constraints deserve emphasis: with pathlen and EKU they are one of only
three mechanisms a third-party verifier enforces. A per-tenant intermediate
constrained to that tenant's namespace makes isolation a property of the
certificate rather than of this library being bug-free.

### 10.4 Regime

```go
type Config struct {
	Subject  pkix.Name
	Depth    int           // D >= 2; frozen forever
	Validity time.Duration // root span, ~10y
	Suite    Suite
	Policy   Policy
	RootKey  KeySource
}

func (r *Regime) Root() *Root
func (r *Regime) Suite() Suite
func (r *Regime) Depth() int
func (r *Regime) Find(path string) (Authority, error)
func (r *Regime) Close() error
```

---

## 11. Wire formats

### 11.1 Regime marker

```
TernstackRegimeInfo ::= SEQUENCE {
    version     INTEGER (1),
    rootHash    [0] IMPLICIT OCTET STRING OPTIONAL,  -- in anchorCert
    anchorHash  [1] IMPLICIT OCTET STRING OPTIONAL } -- in certs we issue
```

Carried under a **private-arc OID** — `1.3.6.1.4.1.<PEN>.1`. A private arc is
*less* non-standard than overloading a subject DN or SAN with custom content, and
avoids colliding with name constraints the tenant may apply. **An IANA PEN must
be registered before shipping**; a squatted arc that later collides is a
compatibility problem for an embedded library.

Always **non-critical**. One OID and one versioned SEQUENCE so new fields never
require a new OID.

Placement: **intermediates and leaf CAs**; opt-in for end-entity certificates.
Measured cost is +77 bytes per certificate per handshake, and a leaf's provenance
is already recoverable from its issuer.

```go
// ReadProvenance returns the UNVERIFIED marker. It is not a trust statement:
// anyone holding any CA key can write any value here. Use VerifyBundle.
func ReadProvenance(c *x509.Certificate) (Provenance, bool)
```

### 11.2 Bundle

```go
type Bundle struct {
	Leaf      *x509.Certificate
	LeafChain []*x509.Certificate // issuers only, parent..root; last is self-signed

	Anchor      *x509.Certificate   // nil when self-anchored
	AnchorChain []*x509.Certificate // issuers only, parent..tenant root
}

func ParseBundle([]byte) (*Bundle, error)
func (b *Bundle) Marshal() ([]byte, error)
func (b *Bundle) PEM() []byte // human inspection only
```

`LeafChain` excludes the leaf. `ParseBundle` **validates** that each terminal
element is self-signed and that every element issued its predecessor — ordering
is attacker-supplied and must not be assumed. The canonical form is a structured
envelope; a flat PEM concatenation is ambiguous between the two chains.

---

## 12. The tenant contract

Reduced to a single clause, but a non-negotiable one:

> **The tenant CA must copy our OID extension verbatim into the issued
> certificate.**

Everything else — DN, pathlen, CA bit, validity — is the tenant's to choose.

This is the design's single point of failure. Measured: a profile-applying CA
drops the extension *and* rewrites the subject, and with the extension stripped
the scheme yields nothing (`step5: no root attestation`). Several enterprise CA
products support extension passthrough via custom profiles or templates, but it
is **off by default and must be requested**. Confirm it is achievable in the
tenant's stack before building on it; `Install` fails loudly rather than
producing a regime that silently is not attested.

Fallbacks if passthrough is impossible:

1. **`anchorKey == rootKey`** — the tenant's signature then covers the root's
   SPKI directly and no custom extension is needed anywhere; the back-check
   becomes an SPKI comparison. Unavailable when the tenant's KMS must generate
   the key.
2. **A detached attestation** — CMS/JWS signed over `hash(rootCert)`, stored
   alongside the bundle. Less elegant, works with any tenant that can sign
   anything.

---

## 13. Verification API

Two callers, two entry points.

```go
// Regime side: validate one of our own certificates and assemble the
// shippable bundle. Also where suite and pathlen drift are caught.
func (r *Regime) Verify(c *x509.Certificate, o VerifyOpts) (*Bundle, error)

// Relying-party side: no Regime, no Store, no keys. This is the function
// that runs on the far end of the wire.
func VerifyBundle(b *Bundle, o VerifyOpts) error

type VerifyPolicy uint8

const (
	// Strict: the leaf's referenced anchor must be current and unrevoked.
	// Fail-closed; the tenant's revocation is a real kill switch.
	Strict VerifyPolicy = iota

	// Loose: any current anchor attesting hash(rootCert) that chains to a
	// trusted tenant root. For one regime attested by several tenants.
	Loose
)

type VerifyOpts struct {
	// Exactly one establishes trust. See §4.4.
	RootPin     []byte
	TenantRoots *x509.CertPool

	Policy  VerifyPolicy
	Now     time.Time
	Anchors []*x509.Certificate // known anchors, for Loose

	// REQUIRED when TenantRoots is set. x509.Verify performs NO CRL or OCSP
	// checking, so without this the tenant can never withdraw consent.
	CheckRevocation func(*x509.Certificate) error
}
```

No separate `Attestation` type: after a successful verify the Bundle already
carries every answer — `AnchorChain[len-1]` *is* the tenant root that vouched.

Strict versus Loose is a **verifier policy, not a certificate format change**.
The same certificates support both. Ship Strict as the default.

---

## 14. Errors

```go
var (
	ErrDepthExceeded       = errors.New("regime: hierarchy depth exceeded")
	ErrNotTerminal         = errors.New("regime: leaf CA only legal at depth D-1")
	ErrSuiteMismatch       = errors.New("regime: artifact does not conform to suite")
	ErrAnchorKeyMismatch   = errors.New("install: cert public key != anchorKey")
	ErrAttestationStripped = errors.New("install: tenant CA did not carry our extension")
	ErrAnchorExpired       = errors.New("verify: referenced anchor is expired")
	ErrAnchorRevoked       = errors.New("verify: referenced anchor is revoked")
	ErrBackCheckFailed     = errors.New("verify: anchor attests a different root")
	ErrRootPinMismatch     = errors.New("open: root does not match supplied pin")
	ErrSealVersion         = errors.New("seal: unknown format version")
)
```

---

## 15. Deliberately absent

Carried over from the security audit of the existing code, each of these removes
a class of defect rather than a single bug:

- **Any `create bool`.** Replaced by distinct `NewRegime` / `OpenRegime` /
  builder entry points.
- **Passphrases below the `SeedGuard`.** The Store never sees one, so the
  audit's H3 (RFC 1423 legacy PEM key encryption, MD5-KDF + unauthenticated CBC)
  and H4 (passphrase interpolated into an error string) cannot recur.
- **CN-keyed lookup.** M5: re-issuing a CN silently orphaned a live,
  unrevocable certificate.
- **A global CRL.** M8: signed by whichever CA was in hand; conforming verifiers
  must ignore non-issuer CRLs.
- **`SignCert(*x509.Certificate)`.** M3: an unauthenticated signing oracle with
  no proof-of-possession, no validity clamping, and caller-controlled extensions
  passed through to signature.
- **JSON import/export.** H1 (exported the DB master key and all private keys in
  plaintext), H2 (wrong password silently corrupted the DB via a shadowed
  error), M1, M2, M7, M9 all lived here.

---

## 16. Empirical basis

Every measured claim in this document was produced against the Go 1.26 toolchain
by standalone programs. They convert directly into regression tests, and the two
that matter most are the forgery case and the stripped-extension case, because
both fail in ways that superficially resemble success.

| Area | Establishes |
|---|---|
| pathlen semantics | ceiling-not-floor; anchor pathlen enforced by Go; `pathlen=0` blocks sub-CAs |
| `MaxPathLenZero` | `MaxPathLen:0` alone silently emits an unconstrained CA |
| DN rewrite | adding one `OU=` orphans a cross-certified hierarchy |
| CSR passthrough | a profile-applying CA drops extensions and rewrites the subject |
| staple | back-check rejects forgery; stripped extension rejected at step 5 |
| stock verifier | forged leaf is indistinguishable without step 6 |
| seal | context binding rejects record relocation; version byte authenticated |

---

## 17. Open items

1. **IANA PEN** must be registered before the OID is baked into any stored
   artifact.
2. **Migration** from the existing boltdb format is unspecified. Given the audit
   findings in the export path, a documented export-then-reissue is likely safer
   than an importer.
3. **`RootPin` representation** — SPKI hash versus full-certificate hash. SPKI
   survives root-certificate renewal; the 10-year root span makes this largely
   theoretical but it should be decided, not defaulted.
4. **Concurrency model** — single-writer versus multi-writer via `Store.CAS`
   needs to be stated normatively rather than left to the backend.
