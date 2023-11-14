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

This memo defines X-Wing, a general-purpose post-quantum/traditional
    hybrid key encapsulation mechanism (PQ/T KEM)
    built on X25519 and ML-KEM-768.

--- middle

# Introduction

## Warning: ML-KEM-768 has not been standardised

X-Wing uses ML-KEM-768, which has not been standardised yet.
Thus X-Wing is not finished, yet, and should not be used, yet.

## Motivation

There are many choices that can be made when
    specifying a hybrid KEM:
    the constituent KEMs;
    their security levels;
    the combinber;
    and the hash within, to name but a few.
Having too many similar options are a burden to the ecosystem.
The aim of X-Wing is to provide a concrete, simple choice
    for post-quantum hybrid KEM,
    that should be suitable for the vast majority of use cases.

## Design goals

1. By making concrete choices, we can simplify and improve  many
   aspects of X-Wing as compared to a more generic combiner.

    - Simplicity of definition. For one, because all shared secrets
       and cipher texts are fixed length, we do not need to encode the length.

    - Its security analysis. Because ML-KEM-768 already assumes QROM, we
       do not need to complicate the analysis of X-Wing by considering
       weaker models.

    - Its performance. By using SHA3-256 in the combiner, which matches
       the hashing in ML-KEM, this hash can be computed in one go on platforms
       where two-way Keccak is available.

2. We aim for "128 bits" security (NIST PQC level 1).
   Although at the moment there is no
	peer-reviewed evidence that ML-KEM-512 does not reach this
	level, we would like to hedge against future cryptanalytic
	improvements, and feel ML-KEM-768 provides a comfortable
	margin.

3. We aim for X-Wing to be usable for most applications,
    including specifically HPKE {{RFC9180}}.

## Not an interactive key-agreement

Traditionally most protocols use a Diffie-Hellman (DH) style
    non-interactive key-agreement.
In many cases, a DH key agreement can be replaced by
    the interactive key-agreement afforded by a KEM
    without change in the protocol flow.
One notable example is TLS {{HYBRID}} {{XYBERTLS}}.
However, not all uses of DH can be replaced  in a straight-forward
    manner by a plain KEM.

## Not an authenticated KEM

In particular, X-Wing is not, borrowing the language
    of {{RFC9180}}, an *authenticated* KEM.

## Comparisons

X-Wing is most similar to HPKE's X25519Kyber768Draft00 {{XYBERHPKE}}.
The differences are:

1. X-Wing uses the final version of ML-KEM-768.

2. X-Wing hashes the shared secrets, to be usable outside of HPKE.

3. X-Wing has a simpler combiner by flattening DHKEM(X25519)
   into the final hash.

There is also a different KEM called X25519Kyber768Draft00 {{XYBERTLS}}
which is used in TLS. This one should not be used outside of TLS,
as it assumes the presence of the TLS transcript to ensure non malleability.

TODO comparison with {{I-D.ounsworth-cfrg-kem-combiners}}

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document is consistent with all terminology defined in
{{I-D.driscoll-pqt-hybrid-terminology}}.

`concat(a, b)` returns the concatenation of byte strings.

`random(n)` returns `n` bytes from a cryptographically secure
    random number generator.

# Construction

## Key derivation

An X-Wing keypair (private key, public key) is derived from entropy
as follows.

~~~
def DeriveKeyPair(ikm):
  seed = SHAKE128(ikm, 96)
  seed1 = seed[0:32]
  seed2 = seed[32:96]
  pk1 = X25519(seed1, 9)
  (sk2, pk2) = ML-KEM-768.DeriveKeyPair(seed2)
  return concat(seed1, sk2), concat(pk1, pk2)

def GenerateKeyPair():
  return DeriveKeyPair(random(32))
~~~

Here X25519() is the function defined in {{Section 5 of RFC7748}}. Note
that 9 corresponds to the standard base point.

ML-KEM-768.DeriveKeyPair() is the function defined in TODO.

ikm SHOULD be at least 32 bytes in length.

## Encapsulation

Given an X-Wing public key `pk`, encapsulation proceeds as follows.

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
  esk1 = random(32)
  ct1 = X25519(esk1, 9)
  ss1 = X25519(esk1, pk1)
  (ss2, ct2) = ML-KEM-768.Encapsulate(pk2)
  return (Combiner(ss1, ss2, ct1, ct2, pk1), concat(ct1, ct2))
~~~~

Here ML-KEM-768.Encapsulate() is the function defined in TODO.

XWingDS is the following 48 byte ASCII string

~~~
XWingDS = concat(
    "======>     ",
    " \ \        ",
    " / ||||||||)",
    "======>     "
)
~~~

[ TODO prettier ASCII art ]


## Decapsulation

~~~
def Decapsulate(ct, sk, pk):
  ct1 = ct[0:32]
  ct2 = ct[32:TODO]
  sk1 = sk[0:32]
  sk2 = sk[32:TODO]
  pk1 = pk[0:32]
  ss1 = X25519(ct1, sk1)
  ss2 = ML-KEM-768.Decapsulate(ct2, sk2)
  return Combiner(ss1, ss2, ct1, ct2, pk1)
~~~

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
