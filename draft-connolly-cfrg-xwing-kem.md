---
title: "X-Wing: general-purpose hybrid post-quantum KEM"
abbrev: xwing
category: info

docname: draft-connolly-cfrg-xwing-kem-latest
submissiontype: IRTF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date: 2023-11-08
consensus: true
v: 3
area: "IRTF"
workgroup: "Crypto Forum"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
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
  I-D.ietf-tls-hybrid-design:
  HASHEDDH:
    target: https://eprint.iacr.org/2022/1230.pdf
    title: Group Action Key Encapsulation and Non-Interactive Key Exchange in the QROM
    author:
      -
        ins: Julien Duman
      -
        ins: Dominik Hartmann
      -
        ins: Eike Kiltz
      -
        ins: Sabrina Kunzweiler
      -
        ins: Jonas Lehmann
      -
        ins: Doreen Riepel
  KYBERV302:
    target: https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
    title: CRYSTALS-Kyber, Algorithm Specification And Supporting Documentation (version 3.02)
    author:
      -
        ins: R. Avanzi
      -
        ins: J. Bos
      -
        ins: L. Ducas
      -
        ins: E. Kiltz
      -
        ins: T. Lepoint
      -
        ins: V. Lyubashevsky
      -
        ins: J. Schanck
      -
        ins: P. Schwabe
      -
        ins: G. Seiler
      -
        ins: D. Stehle # TODO unicode in references
    date: 2021
    format:
      PDF: https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
  MLKEM:
    target: https://csrc.nist.gov/pubs/fips/203/ipd
    title: 'FIPS 203 (Initial Draft): Module-Lattice-Based Key-Encapsulation Mechanism Standard'
    author:
      -
        ins: National Institute of Standards and Technology
  SECEST:
    target: https://github.com/pq-crystals/security-estimates
    title: CRYSTALS security estimate scripts
    author:
      -
        ins: L. Ducas
      -
        ins: J. Schanck
  RFC9180:
  RFC7748:
  NISTR3:
    target: https://csrc.nist.gov/News/2022/pqc-candidates-to-be-standardized-and-round-4
    title: 'PQC Standardization Process: Announcing Four Candidates to be Standardized, Plus Fourth Round Candidates'
    author:
      -
        ins: The NIST PQC Team
  HYBRID: I-D.stebila-tls-hybrid-design
  H2CURVE: I-D.irtf-cfrg-hash-to-curve
  XYBERHPKE: I-D.westerbaan-cfrg-hpke-xyber768d00
  XYBERTLS: I-D.tls-westerbaan-xyber768d00

--- abstract

This memo defines X-Wing, a general-purpose post-quantum/traditional hybrid key
encapsulation mechanism (PQ/T KEM) built on X25519 and ML-KEM-768.

--- middle

# Introduction {#intro}

## Warning: ML-KEM-768 has not been standardised

X-Wing uses ML-KEM-768, which has not been standardised yet. Thus X-Wing is not
finished, yet, and should not be used, yet.

## Motivation {#motivation}

There are many choices that can be made when specifying a hybrid KEM: the
constituent KEMs; their security levels; the combinber; and the hash within, to
name but a few. Having too many similar options are a burden to the ecosystem.

The aim of X-Wing is to provide a concrete, simple choice for post-quantum
hybrid KEM, that should be suitable for the vast majority of use cases.

## Design goals {#goals}

By making concrete choices, we can simplify and improve many aspects of X-Wing
as compared to a more generic combiner.

* Simplicity of definition. Because all shared secrets and cipher texts are
  fixed length, we do not need to encode the length. Using SHA3-256,
  we do not need HMAC-based construction.

* Security analysis: because ML-KEM-768 already assumes QROM, we do not need to
  complicate the analysis of X-Wing by considering weaker models.

* Performance: by using SHA3-256 in the combiner, which matches the hashing in
  ML-KEM, this hash can be computed in one go on platforms where two-way Keccak
  is available.

We aim for "128 bits" security (NIST PQC level 1). Although at the moment there
is no peer-reviewed evidence that ML-KEM-512 does not reach this level, we would
like to hedge against future cryptanalytic improvements, and feel ML-KEM-768
provides a comfortable margin.

We aim for X-Wing to be usable for most applications, including specifically
HPKE {{RFC9180}}.

## Not an interactive key-agreement

Traditionally most protocols use a Diffie-Hellman (DH) style non-interactive
key-agreement.  In many cases, a DH key agreement can be replaced by the
interactive key-agreement afforded by a KEM without change in the protocol flow.
One notable example is TLS {{HYBRID}} {{XYBERTLS}}.  However, not all uses of DH
can be replaced in a straight-forward manner by a plain KEM.

## Not an authenticated KEM

In particular, X-Wing is not, borrowing the language of {{RFC9180}}, an
*authenticated* KEM.

## Comparisons

X-Wing is most similar to HPKE's X25519Kyber768Draft00 {{XYBERHPKE}}. The key
differences are:

* X-Wing uses the final version of ML-KEM-768.

* X-Wing hashes the shared secrets, to be usable outside of HPKE.

* X-Wing has a simpler combiner by flattening DHKEM(X25519) into the final hash.

There is also a different KEM called X25519Kyber768Draft00 {{XYBERTLS}} which is
used in TLS. This one should not be used outside of TLS, as it assumes the
presence of the TLS transcript to ensure non malleability.

TODO comparison with {{I-D.ounsworth-cfrg-kem-combiners}}

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

TODO: update the below to be ML-KEM 768 specific

* ML-KEM 768 post-quantum key-encapsulation mechanism (KEM):

  - `ML-KEM-768.GenerateKeyPair()`: Randomized algorithm to generate a key pair `(skX, pkX)`.
  - `ML-KEM-768.DeriveKeyPair(ikm)`: Deterministic algorithm to derive a key pair
    `(skX, pkX)` from the byte string `ikm`, where `ikm` SHOULD have at
    least `Nsk` bytes of entropy (see {{derive-key-pair}} for discussion).
  - `ML-KEM-768.SerializePublicKey(pkX)`: Produce a byte string of length `Npk` encoding the
    public key `pkX`.
  - `ML-KEM-768.DeserializePublicKey(pkXm)`: Parse a byte string of length `Npk` to recover a
    public key. This function can raise a `DeserializeError` error upon `pkXm`
    deserialization failure.
  - `ML-KEM-768.Encap(pkR)`: Randomized algorithm to generate an ephemeral,
    fixed-length symmetric key (the KEM shared secret) and
    a fixed-length encapsulation of that key that can be decapsulated
    by the holder of the private key corresponding to `pkR`. This function
    can raise an `EncapError` on encapsulation failure.
  - `ML-KEM-768.Decap(enc, skR)`: Deterministic algorithm using the private key `skR`
    to recover the ephemeral symmetric key (the KEM shared secret) from
    its encapsulated representation `enc`. This function can raise a
    `DecapError` on decapsulation failure.
  - `ML-KEM-768.AuthEncap(pkR, skS)` (optional): Same as `Encap()`, and the outputs
    encode an assurance that the KEM shared secret was generated by the
    holder of the private key `skS`.
  - `ML-KEM-768.AuthDecap(enc, skR, pkS)` (optional): Same as `Decap()`, and the recipient
    is assured that the KEM shared secret was generated by the holder of
    the private key `skS`.
  - `ML-KEM-768.Nsecret`: The length in bytes of a KEM shared secret produced by this KEM.
  - `ML-KEM-768.Nenc`: The length in bytes of an encapsulated key produced by this KEM.
  - `ML-KEM-768.Npk`: The length in bytes of an encoded public key for this KEM.
  - `ML-KEM-768.Nsk`: The length in bytes of an encoded private key for this KEM.

* X25519 elliptic curve Diffie-Hellman key-exchange defined in {{Section 5 of RFC7748}}:

  - `X25519.GenerateKeyPair()`: Randomized algorithm to generate an X25519 key pair `(skX, pkX)`
  - `X25519.DeriveKeyPair(ikm)`: Deterministic algorithm to derive a key pair `(skX,
    pkX)` from the byte string `ikm`, where `ikm` SHOULD have at least `Nsk`
    bytes of entropy (see {{derive-key-pair}} for discussion).
  - `X25519.SerializePublicKey(pkX)`: Produce a byte string of length `Npk` encoding
    the public key `pkX`.
  - `X25519.DeserializePublicKey(pkXm)`: Parse a byte string of length `Npk` to recover a
    public key. This function can raise a `DeserializeError` error upon `pkXm`
    deserialization failure.
    TODO: lock this down to be DH based on the base point, not just generic X25519 function
  - `X25519.DH(skX, pkY)`: Perform a non-interactive Diffie-Hellman exchange over
    the Montgomery form of the elliptic curve curve25519 using the private key
    `skX` and public key `pkY` to produce a Diffie-Hellman shared secret of
    length `Ndh` as defined in {{Section 5 of RFC7748}}. This function can raise
    a `ValidationError` as described in {{validation}}.
  - `X25519.Ndh`: The length in bytes of a Diffie-Hellman shared secret produced by
    `X25519()`, which is 32.
  - `X25519.Nsk`: The length in bytes of a Diffie-Hellman private key, which is 32.

* Hash functions:

  - `SHAKE128(bytes)`:
  - `SHA3-256(bytes)`:


# X-Wing Construction

## Key derivation {#derive-key-pair}

An X-Wing keypair (private key, public key) is derived from entropy as follows.

~~~

def DeriveKeyPair(ikm):
  seed = SHAKE128(ikm, 96)
  seed1 = seed[0:32]
  seed2 = seed[32:96]
  (sk1, pk1) = X25519.DeriveKeyPair(seed1)
  (sk2, pk2) = ML-KEM-768.DeriveKeyPair(seed2)
  return concat(sk1, sk2), concat(pk1, pk2)

def GenerateKeyPair():
  return DeriveKeyPair(random(32))


TODO: Define SERIALIZE_PUBLIC_KEY

TODO: Define DESERIALIZE_PUBLIC_KEY

TODO: discuss serializing/deserializing private keys
~~~

Here X25519() is the function defined in {{Section 6.1 of RFC7748}}.

ML-KEM-768.DeriveKeyPair() is the function defined in TODO.

ikm SHOULD be at least 32 bytes in length.

## Encapsulation

Given an X-Wing public key `pk`, encapsulation proceeds as follows.

XWingDS is the following 48 byte ASCII string

~~~
XWingDS = concat(
    "======>     ",
    " \ \        ",
    " / ||||||||)",
    "======>     "
)
~~~

TODO: prettier ASCII art

~~~~
def Combiner(ss1, ss2, ct1, ct2, pk1):
  return SHA3-256(concat(
    XWingDS,
    ss1,
    ss2,
    ct1,
    ct2,
    pk1
  ))

def Encapsulate(pk):
  pk1 = pk[0:32]
  pk2 = pk[32:TODO]
  (esk1, ct1) = X25519.GenerateKeyPair()
  ss1 = X25519.DH(esk1, pk1)
  (ss2, ct2) = ML-KEM-768.Encapsulate(pk2)
  ss = Combiner(ss1, ss2, ct1, ct2, pk1)
  ct = concat(ct1, ct2)
  return (ss, ct)

TODO: Define SERIALIZE
~~~~

Here ML-KEM-768.Encapsulate() is the function defined in TODO.


## Decapsulation

~~~

TODO: define DESERIALIZE()

def Decapsulate(ct, sk, pk):
  ct1 = ct[0:32]
  ct2 = ct[32:TODO]
  sk1 = sk[0:32]
  sk2 = sk[32:TODO]
  pk1 = pk[0:32]
  ss1 = X25519.DH(sk1, ct1)
  ss2 = ML-KEM-768.Decapsulate(ct2, sk2)
  return Combiner(ss1, ss2, ct1, ct2, pk1)
~~~

### Validation of Inputs and Outputs {#validation}

The following public keys are subject to validation if the group requires public
key validation: the sender MUST validate the recipient's public key `pkR`; the
recipient MUST validate the ephemeral public key `pkE`; in authenticated modes,
the recipient MUST validate the sender's static public key `pkS`. Validation
failure yields a `ValidationError`.

For X25519, public keys and Diffie-Hellman outputs MUST be validated as
described in {{?RFC7748}}. In particular, recipients MUST check whether the
Diffie-Hellman shared secret is the all-zero value and abort if so.

TODO: fill out ML-KEM-768 public key validation

###

## Use in HPKE

TODO.

# Security Considerations

TODO Security


# IANA Considerations

TODO


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
