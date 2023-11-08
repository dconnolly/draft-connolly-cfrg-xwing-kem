---
title: X-Wing: A general-purpose KEM
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
  I-D.ietf-tls-hybrid-design:
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

This document specifies a general-purpose key encapsulation mechanism (KEM) that
commits to public key material and ciphertext material as part of computing the
shared secret. KEMs with these properties are attractive for protocols that are
looking to replace pure Diffie-Hellman key agreement.


--- middle

# Introduction

A KEM is a three-tuple of algorithms (*KeyGen*, *Encapsulate*, *Decapsulate*):

 - *KeyGen* takes no inputs and generates a private key and a public key;
 - *Encapsulate* takes as input a public key and produces as output
   a ciphertext and a shared secret;
 - *Decapsulate* takes as input a ciphertext and a private key and
   produces a shared secret.

Like DH, a KEM can be used as an unauthenticated key-agreement
protocol, for example in TLS {{HYBRID}} {{XYBERTLS}}.
However, unlike DH, a KEM-based key agreement is *interactive*,
because the party executing Encapsulate can compute its protocol
message (the ciphertext) only after having received the input
(public key) from the party running *KeyGen* and *Decapsulate*.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.

This document is consistent with all terminology defined in
{{I-D.driscoll-pqt-hybrid-terminology}}.


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
