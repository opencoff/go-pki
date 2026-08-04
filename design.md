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
- **Hold no storage.** The library is strictly in-memory; the entire regime
  serializes to a single sealed blob the host persists however it likes.
- Make the hot path (certificate issuance) independent of everything above.

### Non-goals

- Public-web PKI. No CT, no CAA, no ACME.
- Post-quantum or SHA3 *signatures* — not reachable via stdlib (§7).
- Being a certificate transparency log, an OCSP responder, or a TLS stack.
- Defining a storage interface. There is none (§8).

---

## 2. Architecture

Two layers, dependency pointing one way.

```
   ┌─────────────────────────────────────────────┐
   │ Regime          control plane               │
   │   hierarchy, anchor, ceremonies, CRL state   │
   │   in memory; Seal()s to one blob             │
   └────────────────────┬────────────────────────┘
                        │ LeafCA.Issuer()
   ┌────────────────────▼────────────────────────┐
   │ Issuer          data plane                  │
   │   stateless CSR signing; no regime state     │
   │   frequent; hot path                         │
   └─────────────────────────────────────────────┘
                        │ Regime.TrustedRoot()
   ┌────────────────────▼────────────────────────┐
   │ TrustedRoot     the other side of the wire  │
   │   marshalable trust config; Verify() only    │
   └─────────────────────────────────────────────┘
```

An issuing service needs only a leaf-CA key, its chain, and a policy. A relying
party needs only a `TrustedRoot`. Neither needs the Regime.

---

## 3. Vocabulary

| Term | Meaning |
|---|---|
| **rootCert / RootCA** | Self-signed. The operational root of trust; progenitor of every certificate in the regime. ~10-year span. |
| **Intermediate** | A CA between the root and a leaf CA. May issue further CAs. |
| **LeafCA** | Terminal CA. Issues end-entity certificates only. `pathlen 0`. |
| **Issuer** | Stateless signing façade produced by a LeafCA. |
| **anchorCert** | A tenant-signed **end-entity** certificate carrying the root attestation. Not in any signing path. |
| **RoT_Hash** | `SHA-256(rootCert.Raw)`. Embedded in anchorCert by the tenant CA. |
| **RoT_Sig** | Root's signature proving it consented to being named by this anchor (§4.4). |
| **AnchorHash** | `SHA-256(anchorCert.Raw)`. Embedded in every certificate the regime issues. |
| **Depth (D)** | Number of CA levels, rootCert..LeafCA inclusive. Fixed at creation. `D >= 2`. |
| **Bundle** | Shippable set: leaf, its chain to rootCert, anchorCert, its chain to the tenant root. |
| **TrustedRoot** | Marshalable trust configuration exported to relying parties. |
| **sealing key** | Caller-supplied 32 bytes protecting the serialized regime. Typically KMS-held. |

---

## 4. Trust model

### 4.1 Two disjoint trees, joined by a staple

The regime's tree and the tenant's tree share **no certification path**. They are
joined by a pair of hash references:

```
  Tenant Root CA                         rootCert  (self-signed)
       │ signs                                │ signs
       ▼                                      ▼
  anchorCert  ◄── RoT_Hash + RoT_Sig ────  Intermediate…
  (CA:FALSE)                                  │
       ▲                                      ▼
       └────────── AnchorHash ───────────  LeafCA
                                              │
                                              ▼
                                            leaf
```

- The tenant signs a statement containing `hash(rootCert)`. Only the tenant can
  produce it. **This is the approval.**
- The root signs `RoT_Sig`, proving it consented. Only the root holder can
  produce it. **This is the ownership proof.**
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
5. read RoT_Hash + RoT_Sig from anchorCert; verify RoT_Sig under rootCert
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

### 4.4 RoT_Sig: proving the root consented

Without it, `RoT_Hash` is an **unauthenticated claim** — anyone may place any
hash in their anchorCSR. The attack is a confused deputy: Mallory submits an
anchorCSR containing `hash(rootCert_Alice)`; the tenant approves what it believes
is Mallory's regime; the tenant now vouches for a root Mallory does not control,
and relying parties in that tenant's domain begin accepting Alice's certificates.

The anchorCSR proves possession of `anchorKey`. `RoT_Sig` extends
proof-of-possession to `rootKey`:

```
RoT_Sig = Sign(rootSK,
    SHA-256("ternstack/v1/rot-endorsement" || rootCert.Raw || anchorSPKI))
```

Three properties matter:

- **It binds `anchorSPKI`, so it is non-transferable.** A signature over
  `RoT_Hash` alone would be detachable — Mallory could lift Alice's signature
  into Mallory's own CSR under Mallory's anchor key and it would still verify.
- **It is domain-separated.** `rootSK` also signs certificates; a bare signature
  over a digest must never be confusable with a TBSCertificate signature.
- **`anchorSPKI` exists at signing time.** PKCS#10 has no serial number field —
  serials are assigned by the CA at issuance — so a serial cannot be bound.

**Who verifies it.** The tenant *should*, being the party protected, but
realistically an enterprise CA validates the CSR signature, applies a profile,
and never parses a custom OID. The value does not depend on that: **the relying
party verifies `RoT_Sig` at step 5** using `rootCert`, which it already holds.
Mallory cannot produce a valid signature, so the back-check catches the forgery
even if the tenant copied the extension blindly. Verification is therefore
mandatory at the relying party and advisory at the tenant.

`RoT_Sig` is computed once, at the founding ceremony. Re-anchoring needs a fresh
one only if `anchorKey` changes; reusing `anchorKey` across anchor renewals keeps
the root asleep (§9.5).

### 4.5 Transitive trust — the payoff

A relying party may establish trust two ways:

- **`RootPin`** — it already trusts this regime's root. Standard chain
  validation; the staple is not consulted.
- **`TenantRoots`** — it has *never heard of this regime*. Trust arrives
  transitively: the anchor attests `hash(rootCert)` and chains to a tenant root
  the relying party does trust.

The second mode is the reason the architecture exists. A workload configured
only with the corporate root can accept certificates from a regime it was never
told about.

### 4.6 What this does NOT give you

Stated plainly because it reads like a property of the certificate when it is a
property of the verifier:

- **Stock verifiers see nothing.** The marker is a non-critical extension, so
  openssl, curl, browsers, and every sidecar you did not ship ignore it. Marking
  it critical is not an option — unrecognized critical extensions cause outright
  rejection. Measured: a forged leaf validates perfectly against its own root
  under stock X.509 and is indistinguishable without step 6.
- **The floor is not enforceable.** `pathLenConstraint` is a *maximum*; X.509 has
  no minimum-depth mechanism. "Intermediates must be present before a leaf CA"
  is enforced by this library, not by any verifier.
- **A one-clause dependency on the tenant.** If the tenant's CA strips the
  extension, the design yields nothing. See §12.
- **No rollback protection.** The host owns persistence, so restoring an older
  sealed blob un-revokes certificates. The generation counter makes this
  *detectable*; only the host can make it *impossible* (§8.4).

---

## 5. Hierarchy and the pathlen ladder

`Depth D` is frozen at creation and recorded in the sealed regime. `D >= 2`: at
`D == 1` the root would issue end-entity certificates directly, defeating the
invariant and forcing `Root` to grow an `Issuer()` method.

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
emergency; and the sealing key must be protected for ten years (§8.5).

---

## 7. Suites

A `Suite` pins algorithms by slot, is frozen at creation, recorded in the sealed
regime, and **re-validated against every certificate on open**. Validating only
at issuance would let anyone able to substitute a blob downgrade the regime.

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

SHA3 *is* used for the seal KDF (§8.3) and the `RoT_Sig` digest, where no interop
constraint applies.

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

## 8. Persistence: there isn't any

The library defines **no storage interface**. The entire regime serializes to one
sealed blob; the host persists it in whatever database it already runs.

```go
// Seal serializes the whole regime and encrypts it under key (32 bytes,
// caller-supplied — typically KMS-held). The caller persists the result.
func (r *Regime) Seal(key []byte) ([]byte, error)

// OpenRegime is a package-level constructor, not UnmarshalBinary: a Regime
// carries invariants (suite conformance, the pathlen ladder, root pin, anchor
// back-check) that must hold before the value exists, and a method-based
// unmarshaler would require a half-constructed Regime to mutate toward validity.
func OpenRegime(sealed, key []byte, o OpenOpts) (*Regime, error)

// Generation is a monotonic counter, incremented on every Seal.
func (r *Regime) Generation() uint64

// PeekGeneration reads the generation WITHOUT the sealing key, so a host can
// compare-and-swap on the blob without being able to decrypt it.
func PeekGeneration(sealed []byte) (uint64, error)
```

### 8.1 Why the caller supplies the sealing key

Key provenance stays the caller's decision — KMS-generated, HSM-derived,
whatever. A library-minted key would have to be returned from `Seal`, making an
apparently idempotent method secretly create a secret, and would force the KMS
copy to be updated on every write. Caller-supplied keeps the key stable across
re-seals.

### 8.2 What is in the blob

- `rootCert` + `rootKey`
- every Intermediate and LeafCA, with keys
- `anchorCert` and its chain to the tenant root
- suite, depth, subject, policy
- CRL state: revoked serials and per-issuer CRL numbers

**Not** in the blob: issued end-entity certificates. Serials are 128 random bits
with no counter, and `Revoke` takes a serial supplied by the caller, so there is
nothing to retain. Blob size is therefore a handful of CA certificates plus a
revocation list — kilobytes, and re-sealing the whole thing per mutation is
cheap.

**All operational CA keys live in the blob.** There is no per-node external-signer
custody and no rebinding hook on open, because a resolver callback is exactly the
storage-shaped complexity this model exists to remove. `anchorKey` is the one
external key: it is KMS-resident, signs only the anchorCSR for proof-of-possession,
and is never needed again once `anchorCert` is in the blob.

### 8.3 Seal format

```
version(1) || generation(8) || salt(16) || AES-256-GCM(k, n, state, aad)

k, n = HKDF-SHA3-512(sealingKey, salt=salt,
                     info="ternstack/v1/regime", len=44)
       k = prk[:32], n = prk[32:44]
aad  = version || generation
```

Overhead is 41 bytes. The generation lives in the **cleartext** header so a host
can read it without the key, and in the **AAD** so it cannot be forged.

**Why not a fixed key plus a random nonce.** The regime is re-sealed on every
mutation. With a fixed key you must guarantee nonce uniqueness across an
unbounded number of writes, and random 96-bit nonces put you on a birthday bound
that limits GCM to roughly 2³² invocations per key. Re-deriving the key from a
fresh 16-byte salt each time means collision requires 128 bits instead, and NIST's
per-key ceiling does not apply.

The construction was validated end to end; the same context-separation and
version-authentication behaviour holds:

```
flipped a ciphertext bit     -> REJECTED: cipher: message authentication failed
flipped a salt bit           -> REJECTED: cipher: message authentication failed
bumped the version byte      -> REJECTED: unknown seal version 2
wrong info/context string    -> REJECTED: cipher: message authentication failed
```

### 8.4 Concurrency and rollback

**Single-writer is the normative model.** The hot path is `Issuer`, which is
stateless and never touches regime state, so mutations (creating a CA, revoking)
are rare. A host that needs more can compare-and-swap on `PeekGeneration`.

**Rollback is the host's responsibility, and this is a real reduction in what the
library guarantees.** Restoring an older blob un-revokes certificates and rewinds
CRL numbers. The generation counter makes that detectable; nothing in the library
can prevent it. Any deployment that treats revocation as security-relevant must
enforce monotonicity in its own storage layer.

### 8.5 Key handling

The sealing key protects everything — every CA private key in the regime. Two
consequences:

- **Sealing key and sealed blob must not share a backup.** Co-located, the seal
  is decorative.
- **"Cold root" is now an access-control property, not a custody property.**
  Anyone who can open the regime holds the root key. Protecting the root means
  restricting who can obtain the sealing key from the KMS, and opening the regime
  only during ceremonies.

---

## 9. Lifecycle

### 9.1 Self-anchored

```go
func NewRegime(cfg *Config) (*Regime, error)
```

Generates `rootKey`, self-signs `rootCert` with `pathlen = D-1`. Issued
certificates carry no `AnchorHash`. Nothing is persisted until `Seal`.

### 9.2 Tenant-anchored — a ceremony, not a constructor

```go
func NewRegimeBuilder(cfg *Config, anchorKey crypto.Signer) (*RegimeBuilder, []byte, error)

func (rb *RegimeBuilder) AnchorCSR() []byte
func (rb *RegimeBuilder) RootHash() []byte
func (rb *RegimeBuilder) Seal(key []byte) ([]byte, error)
func OpenRegimeBuilder(sealed, key []byte) (*RegimeBuilder, error)
func (rb *RegimeBuilder) Install(anchorCert []byte, caChain [][]byte) (*Regime, error)
```

The builder generates `rootKey`, self-signs `rootCert`, and produces an
anchorCSR carrying `RoT_Hash` and `RoT_Sig` under the regime OID. `anchorKey` is
a KMS-resident `crypto.Signer` whose only purpose is CSR proof-of-possession.

**The builder is sealable.** The tenant round-trip runs on ticket-queue time; a
process restart must not destroy an approval that took weeks to obtain. The
builder's blob uses `info = "ternstack/v1/builder"`.

**Nothing can be issued before `Install`** — every issued certificate embeds
`hash(anchorCert)`, so the anchor must exist first. The builder state is not
optional ceremony; it is a data dependency.

`Install` validates, with a distinct error for each:

1. `anchorCert.PublicKey` matches **`anchorKey`** (not `rootKey`)
2. the regime OID is present and `RootHash == hash(rootCert.Raw)` →
   `ErrAttestationStripped`
3. `RoT_Sig` verifies under `rootCert` over this anchor's SPKI
4. `caChain` verifies `anchorCert` to a self-signed root
5. `anchorCert` is not revoked

Deliberately **not** required: subject DN preservation, `pathLenConstraint`,
`CA:TRUE`. See §4.2.

### 9.3 Opening

```go
type OpenOpts struct {
	Pin RootPin   // expected root identity, supplied OUT OF BAND
	Now time.Time
}
```

`Pin` must not come from the same place as the blob; otherwise substituting the
blob substitutes the trust anchor with it. Open also re-validates suite
conformance and the pathlen ladder across every loaded certificate.

There is no `create bool`. A boolean that switches between "read this" and
"initialize this" is a latent data-loss bug — in the predecessor code it is
precisely what allowed a wrong password to silently overwrite a live root CA.

### 9.4 Re-anchoring

```go
func (r *Regime) Anchor() *Anchor
func (r *Regime) AnchorExpiresIn() time.Duration
func (r *Regime) Reanchor() (*RegimeBuilder, error)
```

Anchors form a **series over one stable root**: anchor₁, anchor₂, … each carrying
the identical `RoT_Hash`, each independently sufficient for the back-check. New
leaves bind to the current anchor; leaf clamping (§6) means older leaves expire
before their anchor does.

Reusing `anchorKey` across renewals keeps `RoT_Sig` valid and avoids waking the
root for each re-anchor.

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
and its presence in the predecessor code is a copy-forward mistake. `nsCertType`
is dropped entirely.

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
conforming verifiers; the predecessor code signed one global list with whichever
CA happened to be in hand. Each authority keeps its own set and monotonic CRL
number in the sealed state.

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
}

func (r *Regime) Root() *Root
func (r *Regime) Suite() Suite
func (r *Regime) Depth() int
func (r *Regime) Find(path string) (Authority, error)
func (r *Regime) TrustedRoot() *TrustedRoot
```

---

## 11. Wire formats

### 11.1 Regime marker

```
TernstackRegimeInfo ::= SEQUENCE {
    version     INTEGER (1),
    rootAttest  [0] IMPLICIT SEQUENCE {          -- in anchorCert
        rootHash    OCTET STRING,                -- SHA-256(rootCert.Raw)
        sigAlg      AlgorithmIdentifier,
        rootSig     OCTET STRING                 -- §4.4
    } OPTIONAL,
    anchorHash  [1] IMPLICIT OCTET STRING OPTIONAL } -- in certs we issue
```

`sigAlg` is explicit rather than derived from suite knowledge, so a verifier
holding only `rootCert` and the extension can check `RoT_Sig` unambiguously.

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
// anyone holding any CA key can write any value here. Use TrustedRoot.Verify.
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

### 11.3 TrustedRoot

What a Regime exports for the other side of the wire.

```go
type TrustedRoot struct {
	Root          *x509.Certificate   // self-signed regime root
	Intermediates []*x509.Certificate // every Intermediate and LeafCA

	Anchor      *x509.Certificate   // nil when self-anchored
	AnchorChain []*x509.Certificate // empty when self-anchored
}

func (r *Regime) TrustedRoot() *TrustedRoot

// Verify runs the full six-step check of §4.3 against this trust config.
// extra supplies any certificates the peer presented that are not embedded.
func (t *TrustedRoot) Verify(c *x509.Certificate, o VerifyOpts,
	extra ...*x509.Certificate) error

// Fingerprint identifies this configuration for out-of-band pinning.
func (t *TrustedRoot) Fingerprint() []byte

func ParseTrustedRoot([]byte) (*TrustedRoot, error)
func (t *TrustedRoot) MarshalBinary() ([]byte, error)
func (t *TrustedRoot) UnmarshalBinary([]byte) error
```

**Certificates, not bare public keys.** With bare keys you lose subject DNs (so
no path building), pathLenConstraint, name constraints, EKU nesting, validity
windows, and serials for revocation matching — verification would degenerate to
"is this signed by one of these keys," discarding nearly everything this design
makes externally enforceable.

**Serialization solves transport, not trust establishment.** A marshalable
TrustedRoot is a *substitutable* TrustedRoot; delivered over an unauthenticated
channel it is a trust-substitution vector, exactly the reasoning that puts
`RootPin` out of band. `Fingerprint()` exists so deployments can pin it.

Embedding `Intermediates` keeps `Verify` a one-argument call at the cost of
redistribution when the hierarchy grows; `extra` covers the case where the peer
supplies its own chain instead.

When `Anchor` is nil but the presented certificate carries an `AnchorHash`, the
marker is **ignored** — trust derives from the pinned root, and the staple is
additive.

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

// Relying-party side: no Regime, no keys, no state. TrustedRoot.Verify (§11.3)
// is the primary entry point; VerifyBundle covers peers that ship a full bundle.
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
	// Exactly one establishes trust. See §4.5.
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
	ErrRoTSigInvalid       = errors.New("install: root endorsement signature invalid")
	ErrAnchorExpired       = errors.New("verify: referenced anchor is expired")
	ErrAnchorRevoked       = errors.New("verify: referenced anchor is revoked")
	ErrBackCheckFailed     = errors.New("verify: anchor attests a different root")
	ErrRootPinMismatch     = errors.New("open: root does not match supplied pin")
	ErrSealVersion         = errors.New("seal: unknown format version")
	ErrSealCorrupt         = errors.New("seal: authentication failed")
)
```

---

## 15. Deliberately absent

Each of these removes a class of defect found in the predecessor implementation
rather than a single bug. They are recorded here because the reasoning is the
justification for several structural choices above.

- **Any `create bool`.** The old `New(cfg, dbname, create)` shadowed the
  wrong-password error when a JSON payload was present, then proceeded to
  overwrite a live root CA with records encrypted under a nil key — and returned
  success. Replaced by distinct `NewRegime` / `OpenRegime` / builder entry points.
- **Passphrases below the sealing layer.** The old code encrypted per-certificate
  private keys with RFC 1423 legacy PEM encryption (`x509.EncryptPEMBlock`),
  deprecated in Go as insecure by design: MD5-based single-iteration key
  derivation and unauthenticated CBC. It also interpolated the passphrase
  verbatim into an error string. Neither can recur when nothing below the seal
  sees a passphrase.
- **Plaintext export.** The old `ExportJSON` emitted the database master key, the
  KDF salt, and every private key in the clear; anyone holding an export owned
  the entire PKI. There is no export path in this design.
- **CN-keyed lookup.** Certificates were keyed by CommonName, so re-issuing a CN
  silently overwrote the record while the original certificate remained
  cryptographically valid — untrackable, unrevocable, invisible to any CRL.
- **A global CRL.** The old `crl()` signed one list with whichever CA instance
  the method was called on, so revocations issued by other CAs appeared in a CRL
  signed by a non-issuer, which conforming verifiers must ignore. It also used
  the deprecated v1 `Certificate.CreateCRL`, producing CRLs without CRLNumber or
  AKI extensions.
- **`SignCert(*x509.Certificate)`.** An unauthenticated signing oracle: it took a
  caller-supplied certificate template rather than a CSR, so no proof of
  possession was ever verified, and passed caller-controlled validity, KeyUsage,
  ExtKeyUsage and extensions through to signature almost verbatim.
- **Uniform associated data.** Every encrypted record used the same AD, so a
  record could be relocated between buckets — a client certificate moved into the
  server bucket decrypted happily. The seal's context string (§8.3) makes each
  blob decryptable only in its own slot.
- **JSON import.** Beyond the export problem, the importer wrote the serial under
  a different key than the reader used, stored revoked entries in a format no
  reader could parse, dereferenced `pem.Decode` results without nil checks, and
  verified no signature on anything it ingested.

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
| CSR structure | PKCS#10 carries no serial number; `anchorSPKI` is the bindable field |
| staple | back-check rejects forgery; stripped extension rejected at step 5 |
| stock verifier | forged leaf is indistinguishable without step 6 |
| seal | context binding rejects relocation; version byte authenticated |

---

## 17. Open items

1. **IANA PEN** must be registered before the OID is baked into any issued
   certificate.
2. **Migration** from the existing boltdb format is unspecified. Given the
   findings in §15, a documented export-then-reissue is safer than an importer.
3. **`RootPin` representation** — SPKI hash versus full-certificate hash. SPKI
   survives root-certificate renewal; the 10-year root span makes this largely
   theoretical but it should be decided, not defaulted.
4. **CRL state growth.** Revoked serials accumulate in the blob for the life of
   the regime. Pruning entries whose certificates have expired is safe and
   probably necessary; the policy should be explicit.
