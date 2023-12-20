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
  FIPS202:
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    title: 'FIPS 202: SHA-3 Standard: Permutation-Based Hash and
Extendable-Output Functions'
    author:
      -
        ins: National Institute of Standards and Technology
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
  TLSIANA: I-D.ietf-tls-rfc8447bis

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
constituent KEMs; their security levels; the combiner; and the hash within, to
name but a few. Having too many similar options are a burden to the ecosystem.

The aim of X-Wing is to provide a concrete, simple choice for post-quantum
hybrid KEM, that should be suitable for the vast majority of use cases.

## Design goals {#goals}

By making concrete choices, we can simplify and improve many aspects of X-Wing.

* Simplicity of definition. Because all shared secrets and cipher texts are
  fixed length, we do not need to encode the length. Using SHA3-256,
  we do not need HMAC-based construction. For the concrete choice of ML-KEM-768,
  we do not need to mix in its ciphertext, see {{secc}}.

* Security analysis. Because ML-KEM-768 already assumes QROM, we do not need to
  complicate the analysis of X-Wing by considering stronger models.

* Performance. Not having to mix in the ML-KEM-768 ciphertext is a nice performance
  benefit. Furthermore, by using SHA3-256 in the combiner, which matches the hashing in
  ML-KEM-768, this hash can be computed in one go on platforms where two-way Keccak
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

## Not an authenticated KEM {#auth}

In particular, X-Wing is not, borrowing the language of {{RFC9180}}, an
*authenticated* KEM.

## Comparisons

### With HPKE X25519Kyber768Draft00

X-Wing is most similar to HPKE's X25519Kyber768Draft00 {{XYBERHPKE}}. The key
differences are:

* X-Wing uses the final version of ML-KEM-768.

* X-Wing hashes the shared secrets, to be usable outside of HPKE.

* X-Wing has a simpler combiner by flattening DHKEM(X25519) into the final hash.

* X-Wing does not hash in the ML-KEM-768 ciphertext.

There is also a different KEM called X25519Kyber768Draft00 {{XYBERTLS}} which is
used in TLS. This one should not be used outside of TLS, as it assumes the
presence of the TLS transcript to ensure non malleability.

### With generic combiner

The generic combiner of {{I-D.ounsworth-cfrg-kem-combiners}} can be
instantiated with ML-KEM-768 and DHKEM(X25519). That achieves similar
security, but:

* X-Wing is more performant, not hashing in the ML-KEM-768 ciphertext,
  and flattening the DHKEM construction, with the same level of security.

* X-Wing has a fixed 32 byte shared secret, instead of a variable shared secret.

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


* ML-KEM-768 post-quantum key-encapsulation mechanism (KEM), TODO ref:

  - `ML-KEM-768.DeriveKeyPair(ikm)`: Deterministic algorithm to
    derive an ML-KEM-768 key pair `(sk_M, pk_M)` from entropy ikm.
  - `ML-KEM-768.Encapsulate(pk_M)`: Randomized algorithm to generate (ss_M, ct_M),
    an ephemeral 32 byte shared key ss_M,
    and a fixed-length encapsulation (cipher text) of that key ct_M for pk_M.
  - `ML-KEM-768.Decap(ct_M, sk_M)`: Deterministic algorithm using the
    private key `sk_M` to recover the shared key
    from ct_M.

* X25519 elliptic curve Diffie-Hellman key-exchange defined in {{Section 5 of RFC7748}}:

  - `X25519(k,u)`: takes 32 byte strings k and u representing a
    Curve25519 scalar and curvepoint respectively, and returns
    the 32 byte string representing their scalar multiplication.


* Symmetric cryptography.

  - `SHAKE128(message, outlen)`: The extendable-output function (XOF)
    defined in Section 6.2 of {{FIPS202}}.
  - `SHA3-256(message)`: The hash defined in
    defined in Section 6.1 of {{FIPS202}}.


# X-Wing Construction

## Encoding and sizes {#encoding}

X-Wing public key, private key, ciphertexts and shared secrets are all
fixed length byte strings.

 Private key:
 : 2432 bytes

 Public key:
 : 1216 bytes

 Cipher text:
 : 1120 bytes

 Shared secret:
 : 32 bytes

## Key derivation {#derive-key-pair}

An X-Wing keypair (private key, public key) is derived from entropy as follows.

~~~
def DeriveKeyPair(ikm):
  seed = SHAKE128(ikm, 96)
  seed1 = seed[0:32]
  seed2 = seed[32:96]
  (sk1, pk1) = X25519(seed1, 9)
  (sk2, pk2) = ML-KEM-768.DeriveKeyPair(seed2)
  return concat(sk1, sk2), concat(pk1, pk2)

def GenerateKeyPair():
  return DeriveKeyPair(random(32))
~~~

Note that 9 is the standard basepoint for X25519, cf {{Section 6.1 of RFC7748}}.

ikm SHOULD be at least 32 bytes in length.

## Combiner {#combiner}

Given 32 byte strings ss_M, ss_X, ct_X, pk_X, representing the ML-KEM-768
shared secret, X25519 shared secret, X25519 cipher text (ephemeral public key)
and X25519 public key respectively, the combined shared secret is given by:

~~~
def Combiner(ss_M, ss_X, ct_X, pk_X):
  return SHA3-256(concat(
    XWingDS,
    ss_M,
    ss_X,
    ct_X,
    pk_X
  ))
~~~

where XWingDS is the following 8 byte ASCII string

~~~
XWingDS = concat(
    "\oo/",
    "/oo\",
)
~~~

## Encapsulation {#encaps}

Given an X-Wing public key `pk`, encapsulation proceeds as follows.

~~~~
def Encapsulate(pk):
  pk_M = pk[0:1184]
  pk_X = pk[1184:1216]
  ek_X = random(32)
  ct_X = X25519(ek_X, 9)
  ss_X = X25519(ek_X, pk_X)
  (ss_M, ct_M) = ML-KEM-768.Encapsulate(pk_M)
  ss = Combiner(ss_M, ss_X, ct_X, pk_X)
  ct = concat(ct_M, ct_X)
  return (ss, ct)
~~~~

## Decapsulation {#decaps}

~~~
def Decapsulate(ct, sk, pk):
  ct_M = ct[0:1088]
  ct_X = ct[1088:1120]
  sk_M = sk[0:2400]
  sk_X = sk[2400:2432]
  pk_M = pk[0:1184]
  pk_X = pk[1184:1216]
  ss_M = ML-KEM-768.Decapsulate(ct_M, sk_M)
  ss_X = X25519(sk_X, ct_X)
  return Combiner(ss_M, ss_X, ct_X, pk_X)
~~~

## Use in HPKE

X-Wing satisfies the HPKE KEM interface as follows.

The SerializePublicKey, DeserializePublicKey,
SerializePrivateKey and DeserializePrivateKey are the identity functions,
as X-Wing keys are fixed-length byte strings, see {{encoding}}.

DeriveKeyPair is DeriveKeyPair from {{derive-key-pair}}.
The argument ikm to DeriveKeyPair SHOULD be at least 32 octets in length.
(This is contrary to {{RFC9180}} which stipulates it should
be at least Nsk=2432 octets in length.)

Encap is Encapsulate from {{encaps}}.

Decap is Decapsulate from {{decaps}}.

X-Wing is not an authenticated KEM: it does not support AuthEncap()
and AuthDecap(), see {{auth}}.

Nsecret, Nenc, Npk, and Nsk are defined in {{iana}}.

## Use in TLS 1.3

For the client's share, the key_exchange value contains
the X-Wing public key.

For the server's share, the key_exchange value contains
the X-Wing cipher text.

# Security Considerations {#secc}

Informally, X-Wing is secure if SHA3 is secure, and either X25519 is secure, or
ML-KEM-768 is secure.

More precisely, if SHA3-256, SHA3-512, SHAKE-128, and SHAKE-256
may be modelled as a random oracle, then
the IND-CCA security of X-Wing is bounded by the IND-CCA security of
ML-KEM-768, and the gap-CDH security of Curve25519, see TODO.

The security of X-Wing relies crucially on the specifics of the
Fujisaki-Okamoto transformation used in ML-KEM-768.
In particular, the X-Wing combiner cannot be assumed to be secure,
    when used with different KEMs.

# IANA Considerations {#iana}

This document requests/registers a new entry to the "HPKE KEM Identifiers"
registry.

 Value:
 : TBD (please)

 KEM:
 : X-Wing

 Nsecret:
 : 32

 Nenc:
 : 1120

 Npk:
 : 1216

 Nsk:
 : 2432

 Auth:
 : no

 Reference:
 : This document

Furthermore, this document requests/registers a new entry to the TLS Named Group
(or Supported Group) registry, according to the procedures in {{Section 6 of TLSIANA}}.

 Value:
 : TBD (please)

 Description:
 : X-Wing

 DTLS-OK:
 : Y

 Recommended:
 : Y

 Reference:
 : This document

 Comment:
 : PQ/T hybrid of X25519 and ML-KEM-768


# TODO

- Which validation do we want to require?


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
