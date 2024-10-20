---
title: "X-Wing: general-purpose hybrid post-quantum KEM"
abbrev: xwing
category: info

docname: draft-connolly-cfrg-xwing-kem-latest
submissiontype: IRTF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date: 2024-08-19
consensus: true
v: 3
area: "IRTF"
workgroup: "Crypto Forum"
keyword:
 - post quantum
 - kem
 - PQ/T hybrid
venue:
  group: "Crypto Forum"
  type: "Research Group"
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/search/?email_list=cfrg"
  github: "dconnolly/draft-connolly-cfrg-xwing-kem"
  latest: "https://dconnolly.github.io/draft-connolly-cfrg-xwing-kem/draft-connolly-cfrg-xwing-kem.html"

author:
 -
    fullname: Deirdre Connolly
    organization: SandboxAQ
    email: durumcrustulum@gmail.com

 -
    fullname: Peter Schwabe
    organization: MPI-SP & Radboud University
    email: peter@cryptojedi.org

 -
    ins: B.E. Westerbaan
    fullname: Bas Westerbaan
    organization: Cloudflare
    email: bas@cloudflare.com

normative:
  RFC2119:

informative:
  I-D.driscoll-pqt-hybrid-terminology:
  I-D.ounsworth-cfrg-kem-combiners:
  FIPS202:
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    title: 'FIPS 202: SHA-3 Standard: Permutation-Based Hash and
Extendable-Output Functions'
    author:
      -
        ins: National Institute of Standards and Technology
  MLKEM:
    target: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
    title: 'FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard'
    author:
      -
        ins: National Institute of Standards and Technology
  RFC9180:
  RFC7748:
  HYBRID: I-D.stebila-tls-hybrid-design
  XYBERHPKE: I-D.westerbaan-cfrg-hpke-xyber768d00
  XYBERTLS: I-D.tls-westerbaan-xyber768d00
  TLSIANA: I-D.ietf-tls-rfc8447bis
  SCHMIEG:
    target: https://eprint.iacr.org/2024/523
    title: "Unbindable Kemmy Schmidt: ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK"
    author:
      -
        ins: S. Schmieg
  KSMW:
    target: https://eprint.iacr.org/2024/1233
    title: "Binding Security of Implicitly-Rejecting KEMs and Application to BIKE and HQC"
    author:
      -
        ins: J. Kraemer
      -
        ins: P. Struck
      -
        ins: M. Weishaupl
  PROOF:
    target: https://eprint.iacr.org/2024/039
    title: "X-Wing: The Hybrid KEM You’ve Been Looking For"
    author:
      -
        ins: M. Barbosa
      -
        ins: D. Connolly
      -
        ins: J. Duarte
      -
        ins: A. Kaiser
      -
        ins: P. Schwabe
      -
        ins: K. Varner
      -
        ins: B.E. Westerbraan

--- abstract

This memo defines X-Wing, a general-purpose post-quantum/traditional
hybrid key encapsulation mechanism (PQ/T KEM) built on X25519 and
ML-KEM-768.

--- middle

# Introduction {#intro}

## Motivation {#motivation}

There are many choices that can be made when specifying a hybrid KEM:
the constituent KEMs; their security levels; the combiner; and the hash
within, to name but a few. Having too many similar options are a burden
to the ecosystem.

The aim of X-Wing is to provide a concrete, simple choice for
post-quantum hybrid KEM, that should be suitable for the vast majority
of use cases.

## Design goals {#goals}

By making concrete choices, we can simplify and improve many aspects of
X-Wing.

* Simplicity of definition. Because all shared secrets and cipher texts
  are fixed length, we do not need to encode the length. Using SHA3-256,
  we do not need HMAC-based construction. For the concrete choice of
  ML-KEM-768, we do not need to mix in its ciphertext, see {{secc}}.

* Security analysis. Because ML-KEM-768 already assumes the Quantum Random
  Oracle Model (QROM), we do not need to complicate the analysis
  of X-Wing by considering stronger models.

* Performance. Not having to mix in the ML-KEM-768 ciphertext is a nice
  performance benefit. Furthermore, by using SHA3-256 in the combiner,
  which matches the hashing in ML-KEM-768, this hash can be computed in
  one go on platforms where two-way Keccak is available.

We aim for "128 bits" security (NIST PQC level 1). Although at the
moment there is no peer-reviewed evidence that ML-KEM-512 does not reach
this level, we would like to hedge against future cryptanalytic
improvements, and feel ML-KEM-768 provides a comfortable margin.

We aim for X-Wing to be usable for most applications, including
specifically HPKE {{RFC9180}}.

## Not an interactive key-agreement

Traditionally most protocols use a Diffie-Hellman (DH) style
non-interactive key-agreement.  In many cases, a DH key agreement can be
replaced by the interactive key-agreement afforded by a KEM without
change in the protocol flow.  One notable example is TLS {{HYBRID}}
{{XYBERTLS}}.  However, not all uses of DH can be replaced in a
straight-forward manner by a plain KEM.

## Not an authenticated KEM {#auth}

In particular, X-Wing is not, borrowing the language of {{RFC9180}}, an
*authenticated* KEM.

## Comparisons

### With HPKE X25519Kyber768Draft00

X-Wing is most similar to HPKE's X25519Kyber768Draft00
{{XYBERHPKE}}. The key differences are:

* X-Wing uses the final version of ML-KEM-768.

* X-Wing hashes the shared secrets, to be usable outside of HPKE.

* X-Wing has a simpler combiner by flattening DHKEM(X25519) into the
  final hash.

* X-Wing does not hash in the ML-KEM-768 ciphertext.

There is also a different KEM called X25519Kyber768Draft00 {{XYBERTLS}}
which is used in TLS. This one should not be used outside of TLS, as it
assumes the presence of the TLS transcript to ensure non malleability.

### With generic combiner

The generic combiner of {{I-D.ounsworth-cfrg-kem-combiners}} can be
instantiated with ML-KEM-768 and DHKEM(X25519). That achieves similar
security, but:

* X-Wing is more performant, not hashing in the ML-KEM-768 ciphertext,
  and flattening the DHKEM construction, with the same level of
  security.

* X-Wing has a fixed 32 byte shared secret, instead of a variable shared
  secret.

* X-Wing does not accept the optional counter and fixedInfo arguments.

# Requirements Notation

{::boilerplate bcp14-tagged}

# Conventions and Definitions

This document is consistent with all terminology defined in
{{I-D.driscoll-pqt-hybrid-terminology}}.

The following terms are used throughout this document to describe the
operations, roles, and behaviors of HPKE:

- `concat(x0, ..., xN)`: returns the concatenation of byte
  strings. `concat(0x01, 0x0203, 0x040506) = 0x010203040506`.
- `random(n)`: return a pseudorandom byte string of length `n` bytes produced by
  a cryptographically-secure random number generator.

# Cryptographic Dependencies {#base-crypto}

X-Wing relies on the following primitives:


* ML-KEM-768 post-quantum key-encapsulation mechanism (KEM) {{MLKEM}}:

  - `ML-KEM-768.KeyGen_internal(d, z)`: Deterministic algorithm to generate an
    ML-KEM-768 key pair `(pk_M, sk_M)` of an encapsulation key `pk_M`
    and decapsulation key `sk_M`.
    It is the derandomized version of `ML-KEM-768.KeyGen`.
    Note that `ML-KEM-768.KeyGen_internal()` returns the keys in reverse
    order of `GenerateKeyPair()` defined below.
    `d` and `z` are both 32 byte strings.
  - `ML-KEM-768.Encaps(pk_M)`: Randomized algorithm to generate `(ss_M,
    ct_M)`, an ephemeral 32 byte shared key `ss_M`, and a fixed-length
    encapsulation (ciphertext) of that key `ct_M` for encapsulation key `pk_M`.

    `ML-KEM-768.Encaps(pk_M)` MUST perform the encapsulation key check
    of {{MLKEM}} §7.2 and raise an error if it fails.
  - `ML-KEM-768.Decap(ct_M, sk_M)`: Deterministic algorithm using the
    decapsulation key `sk_M` to recover the shared key from `ct_M`.

    `ML-KEM-768.Decap(ct_M, sk_M)` is NOT required  to perform the
    decapsulation key check of {{MLKEM}} §7.3.

  To generate deterministic test vectors, we also use

  - `ML-KEM-768.Encaps_internal(pk_M, m)`: Algorithm to generate `(ss_M, ct_M)`,
    an ephemeral 32 byte shared key `ss_M`, and a fixed-length
    encapsulation (ciphertext) of that key `ct_M` for encapsulation key
    `pk_M`. `m` is a 32 byte string.

    `ML-KEM-768.Encaps_internal(pk_M)` MUST perform the encapsulation key check
    of {{MLKEM}} §7.2 and raise an error if it fails.

* X25519 elliptic curve Diffie-Hellman key-exchange defined in {{Section 5 of RFC7748}}:

  - `X25519(k,u)`: takes 32 byte strings k and u representing a
    Curve25519 scalar and curvepoint respectively, and returns
    the 32 byte string representing their scalar multiplication.
  - `X25519_BASE`: the 32 byte string representing the standard base point
    of Curve25519. In hex
    it is given by `0900000000000000000000000000000000000000000000000000000000000000`.

Note that 9 is the standard basepoint for X25519, cf {{Section 6.1 of RFC7748}}.


* Symmetric cryptography.

  - `SHAKE256(message, outlen)`: The extendable-output function (XOF)
    with that name defined in Section 6.2 of {{FIPS202}}.
  - `SHA3-256(message)`: The hash with that name
    defined in Section 6.1 of {{FIPS202}}.


# X-Wing Construction

## Encoding and sizes {#encoding}

X-Wing encapsulation key, decapsulation key, ciphertexts and shared secrets are all
fixed length byte strings.

 Decapsulation key (private):
 : 32 bytes

 Encapsulation key (public):
 : 1216 bytes

 Ciphertext:
 : 1120 bytes

 Shared secret:
 : 32 bytes

## Key generation

An X-Wing keypair (decapsulation key, encapsulation key) is generated as
follows.

~~~
def expandDecapsulationKey(sk):
  expanded = SHAKE256(sk, 96)
  (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
  sk_X = expanded[64:96]
  pk_X = X25519(sk_X, X25519_BASE)
  return (sk_M, sk_X, pk_M, pk_X)

def GenerateKeyPair():
  sk = random(32)
  (sk_M, sk_X, pk_M, pk_X) = expandDecapsulationKey(sk)
  return sk, concat(pk_M, pk_X)
~~~

`GenerateKeyPair()` returns the 32 byte secret decapsulation key `sk`
and the 1216 byte encapsulation key `pk`.

Here and in the balance of the document for clarity we use
the `M` and `X`subscripts for ML-KEM-768 and X25519 components respectively.

### Key derivation {#derive-key-pair}

For testing, it is convenient to have a deterministic version
of key generation. An X-Wing implementation MAY provide the following
derandomized variant of key generation.

~~~
def GenerateKeyPairDerand(sk):
  sk_M, sk_X, pk_M, pk_X = expandDecapsulationKey(sk)
  return sk, concat(pk_M, pk_X)
~~~

`sk` must be 32 bytes.

`GenerateKeyPairDerand()` returns the 32 byte secret encapsulation key
`sk` and the 1216 byte decapsulation key `pk`.

## Combiner {#combiner}

Given 32 byte strings `ss_M`, `ss_X`, `ct_X`, `pk_X`, representing the
ML-KEM-768 shared secret, X25519 shared secret, X25519 ciphertext
(ephemeral public key) and X25519 public key respectively, the 32 byte
combined shared secret is given by:

~~~
def Combiner(ss_M, ss_X, ct_X, pk_X):
  return SHA3-256(concat(
    ss_M,
    ss_X,
    ct_X,
    pk_X,
    XWingLabel
  ))
~~~

where XWingLabel is the following 6 byte ASCII string

~~~
XWingLabel = concat(
    "\./",
    "/^\",
)
~~~

In hex XWingLabel is given by `5c2e2f2f5e5c`.

## Encapsulation {#encaps}

Given an X-Wing encapsulation key `pk`, encapsulation proceeds as follows.

~~~
def Encapsulate(pk):
  pk_M = pk[0:1184]
  pk_X = pk[1184:1216]
  ek_X = random(32)
  ct_X = X25519(ek_X, X25519_BASE)
  ss_X = X25519(ek_X, pk_X)
  (ss_M, ct_M) = ML-KEM-768.Encaps(pk_M)
  ss = Combiner(ss_M, ss_X, ct_X, pk_X)
  ct = concat(ct_M, ct_X)
  return (ss, ct)
~~~

`pk` is a 1216 byte X-Wing encapsulation key resulting from `GeneratePublicKey()`

`Encapsulate()` returns the 32 byte shared secret `ss` and the 1120 byte
ciphertext `ct`.

Note that `Encapsulate()` may raise an error if the ML-KEM encapsulation
does not pass the check of {{MLKEM}} §7.2.

### Derandomized

For testing, it is convenient to have a deterministic version
of encapsulation. An X-Wing implementation MAY provide
the following derandomized function.

~~~
def EncapsulateDerand(pk, eseed):
  pk_M = pk[0:1184]
  pk_X = pk[1184:1216]
  ek_X = eseed[32:64]
  ct_X = X25519(ek_X, X25519_BASE)
  ss_X = X25519(ek_X, pk_X)
  (ss_M, ct_M) = ML-KEM-768.EncapsDerand(pk_M, eseed[0:32])
  ss = Combiner(ss_M, ss_X, ct_X, pk_X)
  ct = concat(ct_M, ct_X)
  return (ss, ct)
~~~

`pk` is a 1216 byte X-Wing encapsulation key resulting from `GeneratePublicKey()`
`eseed` MUST be 64 bytes.

`EncapsulateDerand()` returns the 32 byte shared secret `ss` and the 1120 byte
ciphertext `ct`.


## Decapsulation {#decaps}

~~~
def Decapsulate(ct, sk):
  (sk_M, sk_X, pk_M, pk_X) = expandDecapsulationKey(sk)
  ct_M = ct[0:1088]
  ct_X = ct[1088:1120]
  ss_M = ML-KEM-768.Decapsulate(ct_M, sk_M)
  ss_X = X25519(sk_X, ct_X)
  return Combiner(ss_M, ss_X, ct_X, pk_X)
~~~

`ct` is the 1120 byte ciphertext resulting from `Encapsulate()`
`sk` is a 32 byte X-Wing decapsulation key resulting from `GenerateKeyPair()`

`Decapsulate()` returns the 32 byte shared secret.

### Keeping expanded decapsulation key around

For efficiency, an implementation MAY cache the result of `expandDecapsulationKey`.
This is useful in two cases:

1. If multiple ciphertexts for the same key are decapsulated.
2. If a ciphertext is decapsulated for a key that has just been generated.
   This happen on the client-side for TLS.

A typical API pattern to achieve this optimization is to have an
opaque decapsulation key object that hides the cached values.
For instance, such an API could have the following functions.

1. `GenerateKeyPair()` returns an encapsulation key and an opaque
    object that contains the expanded decapsulation key.

2. `Decapsulate(ct, esk)` takes a ciphertext and an expanded decapsulation key.

4. `PackDecapsulationKey(sk)` takes an expanded decapsulation key,
    and returns the packed decapsulation key.

3. `UnpackDecapsulationKey(sk)` takes a packed decapsulation key, and returns
    the expanded decapsulation key. In the case of X-Wing this would
    be the same as a derandomized `GenerateKeyPair()`.

The expanded decapsulation key could cache even more computation,
such as the expanded matrix A in ML-KEM.

Any such expanded decapsulation key MUST NOT be transmitted between
implementations, as this could break the security analysis of X-Wing.
In particular, the MAL-BIND-K-PK and MAL-BIND-K-CT binding
properties of X-Wing do not hold when transmitting the regular ML-KEM
decapsulation key.

## Use in HPKE

X-Wing satisfies the HPKE KEM interface as follows.

The `SerializePublicKey`, `SerializePrivateKey`,
and `DeserializePrivateKey` are the identity functions,
as X-Wing keys are fixed-length byte strings, see {{encoding}}.

`DeriveKeyPair()` is given by

~~~
def DeriveKeyPair(ikm):
  return GenerateKeyPairDerand(SHAKE256(ikm, 32))
~~~

where the HPKE private key and public key are the X-Wing decapsulation
key and encapsulation key respectively.

`Encap()` is `Encapsulate()` from {{encaps}}, where an
ML-KEM encapsulation key check failure causes an HPKE `EncapError`.

`Decap()` is `Decapsulate()` from {{decaps}}.

X-Wing is not an authenticated KEM: it does not support `AuthEncap()`
and `AuthDecap()`, see {{auth}}.

Nsecret, Nenc, Npk, and Nsk are defined in {{iana}}.

## Use in TLS 1.3

For the client's share, the key_exchange value contains
the X-Wing encapsulation key.

For the server's share, the key_exchange value contains
the X-Wing ciphertext.

On ML-KEM encapsulation key check failure, the server MUST
abort with an illegal_parameter alert.

# Security Considerations {#secc}

Informally, X-Wing is secure if SHA3 is secure, and either X25519 is
secure, or ML-KEM-768 is secure.

More precisely, if SHA3-256, SHA3-512, and SHAKE-256 may be
modelled as a random oracle, then the IND-CCA security of X-Wing is
bounded by the IND-CCA security of ML-KEM-768, and the gap-CDH security
of Curve25519, see {{PROOF}}.

The security of X-Wing relies crucially on the specifics of the
Fujisaki-Okamoto transformation used in ML-KEM-768: the X-Wing
combiner cannot be assumed to be secure, when used with different
KEMs. In particular it is not known to be safe to leave
out the post-quantum ciphertext from the combiner in the general case.

## Binding properties
Some protocols rely on further properties of the KEM.
X-Wing satisfies the binding properties MAL-BIND-K-PK and MAL-BIND-K-CT
(TODO: reference to proof).
This implies {{KSMW}} X-Wing also satisfies

- MAL-BIND-K,CT-PK
- MAL-BIND-K,PK-CT
- LEAK-BIND-K-PK
- LEAK-BIND-K-CT
- LEAK-BIND-K,CT-PK
- LEAK-BIND-K,PK-CT
- HON-BIND-K-PK
- HON-BIND-K-CT
- HON-BIND-K,CT-PK
- HON-BIND-K,PK-CT

In contrast, ML-KEM on its own does not achieve
MAL-BIND-K-PK, MAL-BIND-K-CT, nor MAL-BIND-K,PK-CT. {{SCHMIEG}}

# IANA Considerations {#iana}

This document requests/registers a new entry to the "HPKE KEM Identifiers"
registry.

 Value:
 : 26287 (0x66af, please)

 KEM:
 : X-Wing

 Nsecret:
 : 32

 Nenc:
 : 1120

 Npk:
 : 1216

 Nsk:
 : 32

 Auth:
 : no

 Reference:
 : This document

Furthermore, this document requests/registers a new entry to the TLS
Named Group (or Supported Group) registry, according to the procedures
in {{Section 6 of TLSIANA}}.

 Value:
 : 26287 (0x66af, please)

 Description:
 : X-Wing

 DTLS-OK:
 : Y

 Recommended:
 : N

 Reference:
 : This document

 Comment:
 : PQ/T hybrid of X25519 and ML-KEM-768

--- back

# Implementations

- Go

  - [CIRCL](https://github.com/cloudflare/circl/pull/471)

  - [Filippo](https://github.com/FiloSottile/mlkem768)

    Note: implements the older `-04` version of this memo at the time of
    writing.

- Rust

  - [xwing-kem.rs](https://github.com/rugo/xwing-kem.rs)

    Note: implements the older `-00` version of this memo at the time of
    writing.


# Machine-readable specification {#S-spec}

For the convenience of implementors, we provide a reference specification
in Python. This is a specification; not production ready code:
it should not be deployed as-is, as it leaks the private key by its runtime.

## xwing.py

~~~~
{::include ./spec/xwing.py}
~~~~

## x25519.py

~~~~
{::include ./spec/x25519.py}
~~~~

## mlkem.py

~~~~
{::include ./spec/mlkem.py}
~~~~

# Test vectors # TODO: replace with test vectors that re-use ML-KEM, X25519 values

~~~~
{::include ./spec/test-vectors.txt}
~~~~

# Acknowledgments

TODO acknowledge.

# Change log

> **RFC Editor's Note:** Please remove this section prior to publication of a
> final version of this document.

## Since draft-connolly-cfrg-xwing-kem-05

- Fix several typos.

## Since draft-connolly-cfrg-xwing-kem-04

- Note that ML-KEM decapsulation key check is not required.

- Properly refer to FIPS 203 dependencies. #20

- Move label at the end. As everything fits within a single block of SHA3-256,
  this does not make any difference.

- Use SHAKE-256 to stretch seed. This does not have any security or performance
  effects: as we only squeeze 96 bytes, we perform a single Keccak permutation
  whether SHAKE-128 or SHAKE-256 is used. The effective capacity of the sponge
  in both cases is 832, which gives a security of 416 bits. It does require
  less thought from anyone analysing X-Wing in a rush.

- Add HPKE codepoint.

- Don't mark TLS entry as recommended before it has been through the
  IETF consensus process. (Obviously the authors recommend X-Wing.)

## Since draft-connolly-cfrg-xwing-kem-03

- Mandate ML-KEM encapsulation key check, and stipulate effect
  on TLS and HPKE integration.

- Add provisional TLS codepoint. (Not assigned, yet.)

## Since draft-connolly-cfrg-xwing-kem-02

- Use seed as private key.

- Expand on caching decapsulation key values.

- Expand on binding properties.

## Since draft-connolly-cfrg-xwing-kem-01

- Add list of implementations.

- Miscellaneous editorial improvements.

- Add Python reference specification.

- Correct definition of `ML-KEM-768.KeyGenDerand(seed)`.

## Since draft-connolly-cfrg-xwing-kem-00

- A copy of the X25519 public key is now included in the X-Wing
  decapsulation (private) key, so that decapsulation does not
  require separate access to the X-Wing public key. See #2.
