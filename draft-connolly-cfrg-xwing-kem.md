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
  - `X25519_BASE`: the 32 byte string representing the standard base point
    of Curve25519. In hex
    it is given by `09000000000000000000000000000000000000000000`.

Note that 9 is the standard basepoint for X25519, cf {{Section 6.1 of RFC7748}}.


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
  seed_M = seed[0:64]
  seed_X = seed[64:96]
  (sk_M, pk_M) = ML-KEM-768.DeriveKeyPair(seed_M)
  (sk_X, pk_X) = X25519(seed_X, X25519_BASE)
  return concat(sk_M, sk_X), concat(pk_M, pk_X)

def GenerateKeyPair():
  return DeriveKeyPair(random(32))
~~~

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

where XWingDS is the following 6 byte ASCII string

~~~
XWingDS = concat(
    "\./",
    "/^\",
)
~~~

## Encapsulation {#encaps}

Given an X-Wing public key `pk`, encapsulation proceeds as follows.

~~~~
def Encapsulate(pk):
  pk_M = pk[0:1184]
  pk_X = pk[1184:1216]
  ek_X = random(32)
  ct_X = X25519(ek_X, X25519_BASE)
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

# Test vectors

~~~
seed   7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26
sk
  1936812cd9a0a24c8c56658a47a23b1dabc8ce4b63fa6a24d10476d176ac2b4961d9f81e
  4a01b050d374e78438c63381798989d34110ed87741d314dfad367d5d9ae60833f19b173
  f0a57ecf269bf5c58e9a2874130177b20b11e8f6215f104773217773611134116fbf2920
  8aa73aaa48969153232916096143c97b764ed5bc5e640c1c0c510c3f2a49d452b8bc630d
  30fb9f3cb1b3201858260cc911837b2e297d46aa2dba5984fd9c0350b16ced3a69a6c5c4
  05400c84561c0cb666326a7c1f6041b832a46140a1f9917a1caa3dd4f02aa8fc22e24121
  47d6431c4acf05ac24dbe647ac008eb6b67ae6f5595df8662133c7e9279e244969c7f76b
  947c99fb7c8264fc6318206694a9bcc331291a04a8e4b97462a26cdb701d6aca50829c68
  b8c64e49d4a5a90047b1349e4d75918eb915dd19abf8618e6666a733d35a62c17f47936b
  0f329b69d07d9b0a8d695225e7392bc5d81e1d101c92ab766fd18987a42606d6060e411f
  dada00ef41051d89c9567074d3cbc3a31a4f2cd378026214577a458968a0bd3894cd1ac0
  56b09450dac31a0ac6f2ab777ab89b473c1cde619bfaea21e7f855e18a6e1104cd9774a9
  56663d2962c970ba2f92d04164230260d91c67c35f8c35827984c2398673845905a34660
  e1788426e923caa348dcda6f862153bff931b5a9cd4524b6b2ec61596327c3272952e634
  3dea5d17998e85c10f073c098c68159b661f443ac2bf8c8b281805829596885039c922a6
  0ecc83e2d92c85e85299bc69043a06d1b17de8ebb0408283840c66096cc0fd340deaa15c
  3bc2c8aa073be1cb3e60da6acc04747b5704d6f40229c8a8abe2ab55c4a581090c1598ad
  ca043c55b4a0854b046df006cf37aff2ac075ce402abe79445cac95e0854f4b80a626412
  ecf53f0d995e57b9cc3d677cd2c6c6e96cce0ba70c414012f4c4394c8939044bb3332a14
  21dc72a08b183d97c75951420661ce04c124b1584e6df85e3b2cbd5d4c58430010851cb7
  a727497d203144ec7f42d6c9a2c573064c5bcd86bb394c72736846698673a806681fa6b2
  54875264a9cbb32357df78559fdbbed8ac1b4628acb0638420b9641fa5415beb442e569c
  330c65e67a912813a5f859a158793bb94829313a2d67c76596098015643a278859515bc9
  1f10b6d5d41d6fd4b543fbcafb3385a906a53c39bf0b7b88399902d65500722c498120c1
  9f604f4488a1afa58b545c36aeb8697bca6f9abc8dcf86378ccb57b6b2403723460f474c
  2b6a99c36b2b49c9a582e33e8e616618e1cb2d7bc5b4006625825f00fa7679ca5a5b771a
  c3948c330c2381f0ce5b6b7ef2525818e2a88f130bf3687cce5c4c56d4c6367a1d26b981
  28b99b2bc94dc530011da84aaa93b4653132a7554e8101a584ca490b58b0be15825c3292
  4190b23cb10afb5ca9ee1bcdf8058150344e12476a71d5a27f26227f19475d1b746de772
  581b92ad62818c7cabe0677d430a60092ac894f8205ff8a22918a3b6f96ae4c3aa633485
  ef6a13b116c1dacb3475c7aea7169c57365edfd3721a5ccb32494e08224c22431dc5db5c
  eed68a22c01951747d44ab480ae6781e270e8d38975cda61a3176c719aaf788c6db7b629
  01baad4f57bc0693c8c32c4dbbf59dedcc9379719af1966da78ca15c295160d767566798
  06ca622e86ab3cca5e7591b4014042ba926306f688eb8c00ea8c6df7f145f7eb44a4d8bb
  298468638194e8e446931c7e044bc9b42625a32b0fdcc6a07b8252f5f2ab1d359573f804
  d5885ec5335f1f27b2d655cd040424971183978b4281c0592ce1b86ec59d08f3914f95ce
  a6426dcd669371b203d42c931c3ca66525900555aebd353300f6c931690368098330c719
  af04449d39932f71a8f701887fd1abf88126a50006197c6c09e46f18e89b089c0f4e6800
  03bb27f0a2a11012bafe324df08c72ce3aabd29593eff543d1488c81817d8557626bec98
  d3e4760890362da09aac999c5f17025caab49565acc0731f8cab5b4651abb743c67e1a57
  648057d3239788b03c19ccae952a373b5b487b3585bf0abf3ba67a6b177561580f2893cd
  35ebaafd4a9efa769b0180cc6a9c37fd65a15c1c7cf6b8773f519cabb4bcbaa97c02a5cd
  fdf19066ca50c746be7893bb9477454bba07349b256f33bfc7b03d0fd57eeddbacf7e856
  355b2c45e41f23e89fd7211e09c3b1d9ca82515ac102883b1ff7c9c84749889110599731
  1db3c4642875cf412c8521167fc21a72813426eb79a4d70cefc79cf14b3721d3a6d00c49
  db04c90d74300cf54847e9ab594609c6baa4513653cbd105942632523713cfca453da496
  49708babfb6a4786c2c7a3839a9331390c9d8143499e48c026a097aec400e8e872aa29c0
  deac0ca6687267d78637bc54b70943e202bae2851000788b13d89ec2f287036b2d941b78
  b3e22fede8926798b8ea85aeb6a9a44002c09a099750cc4551962ca2c0c6b88a119a54c4
  c5317640d7684f81b87a2b23274032160caa8a3b8b1859cec1c85cec2050240b54a1d40d
  359015b62c821d00106545a1c1eb4e5b38c78678b340a7017ccb39fb455eea3a50751108
  cdd53254c1452a7b5440d1b4ed8357faf28e1f9b0936c43b90f4a2052bb68c145a7cf01a
  b76189936ac764d7b95b96b83615ab52019458eacb98b9a7172076cff753e0cc0ff57143
  933bcfa32815cbfa671a1495d0e34df466275d532742e80f0473b5778a18d843abaeea17
  716342ebc8bd2e0597c79361d3b2bbfb444788a2b01e9cb12cc088a2bc55948cc321dab9
  e0db394906a693abadf8967312a709f2995c95810014b87780c38390bc55ee648fbd7bb3
  17f5003c91aa1a76758e328f27ec4a56e981c6a7ad3206a21317b95c28816917c274b19e
  861bc8fe198dc4d241305b0ab09677810b3e24ca08c6b36da03154958a70707c35857c20
  8e51cb8440111467cd721ab397cc2c8c927517f2761068c7db987e857b3cc8303907a385
  63d3ac53509120d30ec243cb6de22b4ed00da2ec482dbc07b328a1404ca98c38b6bd73c4
  893a8ad2197c9b9484e43ba89a970514f3b59899a5c6a15d87f9811cb3c85569a4fff6a6
  3e8c39d8fa9f71f636ae107fa0f765467bab5831aac3787a98ca448df4cefca373fd836c
  5682875e63cf641285f3436fde5540ed901b5f5394dcb6a6cc133c0db09e83b4796ffb4d
  657c374d955c84b41a1302a93611150fd94e7f9b51b27570e4c1b55b439e406bcf1a7a3e
  45e375c87213cd59556c490f0116b67c46333a5d6798d8910fe395aaf7902f1f6ea7970c
  13094e4934bf370306d7124609047e8f6a0c291b98a9fa6172888584b758dc8c73ffd52d
  49089a09ec791d43e4383b4de79d54097547712fcd686b21122d0ea519584f9df3b9a27b
  806229e3c91ebc8a529fa099d0248b7ead51fac8
pk
  01baad4f57bc0693c8c32c4dbbf59dedcc9379719af1966da78ca15c295160d767566798
  06ca622e86ab3cca5e7591b4014042ba926306f688eb8c00ea8c6df7f145f7eb44a4d8bb
  298468638194e8e446931c7e044bc9b42625a32b0fdcc6a07b8252f5f2ab1d359573f804
  d5885ec5335f1f27b2d655cd040424971183978b4281c0592ce1b86ec59d08f3914f95ce
  a6426dcd669371b203d42c931c3ca66525900555aebd353300f6c931690368098330c719
  af04449d39932f71a8f701887fd1abf88126a50006197c6c09e46f18e89b089c0f4e6800
  03bb27f0a2a11012bafe324df08c72ce3aabd29593eff543d1488c81817d8557626bec98
  d3e4760890362da09aac999c5f17025caab49565acc0731f8cab5b4651abb743c67e1a57
  648057d3239788b03c19ccae952a373b5b487b3585bf0abf3ba67a6b177561580f2893cd
  35ebaafd4a9efa769b0180cc6a9c37fd65a15c1c7cf6b8773f519cabb4bcbaa97c02a5cd
  fdf19066ca50c746be7893bb9477454bba07349b256f33bfc7b03d0fd57eeddbacf7e856
  355b2c45e41f23e89fd7211e09c3b1d9ca82515ac102883b1ff7c9c84749889110599731
  1db3c4642875cf412c8521167fc21a72813426eb79a4d70cefc79cf14b3721d3a6d00c49
  db04c90d74300cf54847e9ab594609c6baa4513653cbd105942632523713cfca453da496
  49708babfb6a4786c2c7a3839a9331390c9d8143499e48c026a097aec400e8e872aa29c0
  deac0ca6687267d78637bc54b70943e202bae2851000788b13d89ec2f287036b2d941b78
  b3e22fede8926798b8ea85aeb6a9a44002c09a099750cc4551962ca2c0c6b88a119a54c4
  c5317640d7684f81b87a2b23274032160caa8a3b8b1859cec1c85cec2050240b54a1d40d
  359015b62c821d00106545a1c1eb4e5b38c78678b340a7017ccb39fb455eea3a50751108
  cdd53254c1452a7b5440d1b4ed8357faf28e1f9b0936c43b90f4a2052bb68c145a7cf01a
  b76189936ac764d7b95b96b83615ab52019458eacb98b9a7172076cff753e0cc0ff57143
  933bcfa32815cbfa671a1495d0e34df466275d532742e80f0473b5778a18d843abaeea17
  716342ebc8bd2e0597c79361d3b2bbfb444788a2b01e9cb12cc088a2bc55948cc321dab9
  e0db394906a693abadf8967312a709f2995c95810014b87780c38390bc55ee648fbd7bb3
  17f5003c91aa1a76758e328f27ec4a56e981c6a7ad3206a21317b95c28816917c274b19e
  861bc8fe198dc4d241305b0ab09677810b3e24ca08c6b36da03154958a70707c35857c20
  8e51cb8440111467cd721ab397cc2c8c927517f2761068c7db987e857b3cc8303907a385
  63d3ac53509120d30ec243cb6de22b4ed00da2ec482dbc07b328a1404ca98c38b6bd73c4
  893a8ad2197c9b9484e43ba89a970514f3b59899a5c6a15d87f9811cb3c85569a4fff6a6
  3e8c39d8fa9f71f636ae107fa0f765467bab5831aac3787a98ca448df4cefca373fd836c
  5682875e63cf641285f3436fde5540ed901b5f5394dcb6a6cc133c0db09e83b4796ffb4d
  657c374d955c84b41a1302a93611150fd94e7f9b51b27570e4c1b55b439e406bcf1a7a3e
  45e375c87213cd59556c490f0116b67c46333a5d6798d8910fe395aaf7902f1f9bb6cee3
  f79506960abcda4e65d8197e0c992244dae91c21068915647f844f49
eseed  3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2
ct
  e77c9d09372acb7a39cf6c1f87a9d43a48b8a6f5e78a442ae8661c1b46a1fca325d72c01
  41d0c994851f7cf33c28189d5acbf5fa3ede643dfc7df4bb9e1b6bbc1738442353bb610a
  32b0d14bf238394314af3b6bc75e84f1db85034932be106ba3b5850f1b63fa0896c2079b
  c7c345da78187b0b9968850b343913016d85c557377fb6cf3fbb0a8d502a7dcfa6e0f50c
  6d7d3f5534ca04d666147ce39361bd3fa50916612ff62f06d2a6fafd6ee3f026f146922a
  2a0de5e7ab309ba11ea00345ffa1d0a68bfea6038ae2bb72411aa6c75fe720336e7b87aa
  3740927f0502892a16afdfcdee60e1de6cb4dcfcc578f51e3f48b2c3cdda65664c2029aa
  97e659566927ba1de3f4b46d5f7aec4b1b0c136c4b040f78d2491a7ef8e0629ba08bdfed
  d3b78a330f0ca74725006dcb6d1680f8e85b47a28d1f25cb4cac69756c8cc720afbadac8
  9b2250665fb84fa00c4db9dceab0a3212dd39258b868140c392a64031e1620c7c40db005
  8cfdd21598e82dc4afb89c2b8e6c3f93789b13537abdea4205ef873d360a2709d191b59b
  1e1f462166ea8ffa62408609cdeb08ca30654156e54450083546c0c2cd32514e66de1d1b
  4fc548808b22ba7a7ed54cc1e6fd17253c1f9f814d2896242a90bcb255127ef51329ad83
  9c4f6aaeda5b0257f7ba3739bc5b1618052c5425be4296b356e65bf80655951143b6ffb8
  d909e50283c35070c8c20ac050e206831969420419ff53f999bd6b0df5710ef9650740ac
  4e07c369364396f15f50a5f71e9533803d9715310a3dd11f4dd683cf1a7797ce459f8b4f
  a7043c9552ace783f064b09f5cfc77a432f12e44a7e27642088d7d61f1aad7c816acf835
  c46f65916a9d4ca8cb40f505cfe0f5bb9f0e667ce76718c5696fce9db45be1cd86c879b4
  b4969151231a05460b19c74f63ed9dd08f5554ff763cf4a262a2648f9a200329ed5e1326
  d6af06d6aa1e56742b570ab42e93f21666e4dcf3b91cefa97c2e5fe444d1ceb3d84aff9d
  a89dfd871d207c9495e3038fe8f928da33a69292337021b979cf53ac85e211b012ce9496
  b3f4cad3ad70e14c8b8dbc8c4c2bc1f96e04ecba2c357fae87cc90e1b6bec2db85fbed12
  003fb8966d5591fb82d896356ebc051c712cb162f9ee55d32208e8cee10a5b872b9e5136
  cbaa24c1d4e08ed9289f8fe338be2e4123414e63c4d08e0ffb155965c9a52aa41c2900e2
  3672fb409a0d3368ced9758d55ffa0204a1eeac8a3e3c16694ccb21c68a18a7dd16dc2be
  44b5d08dfc3f4bdd88b8d5aa83ccd98e5fdb83eb2d8b47bf8a8c7198c04284b36b061873
  3f652895b140024bae0f0cccfbfb1eb94662eacaa18d7e8ef485f9661ef9d48dfa9e12a7
  2dd20ea678aa4f820587fe7bef71ce9f984268ef3c34628ef1f431f50988b70e738685bb
  5df4ef1e98d85096eecf92af5775b89eec113bc57611fee91279829269b22a0fbdcee373
  b2a33cfeaf2456fe0b85d7151d91462d6097e95b4c0ea756c8624291866086b4de7c6f82
  06b7c550f97a388d366230bfa51cb2ef0f50a15489a78f8b1b8b63c76cd92472dd032154
  9976ee7c
ss     8162a6bfc9c93615cbaff7f3328a54d1c9b413d9c5165492e3bc423278b25195

seed   35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2
sk
  827667b8072e1608132438b41c756e98c12f76f86cbea3b5fb6033b1e8903783aa6910cd
  2ff275c7c19c096085682c0d5528b264406acdb78c2f9c0ebb094c30fc4778c1974ff739
  a208993ee05eaab5a0c99c82484809a82b9796fb07e09296618aa889dacc7912927d0669
  0ddc6c581359a86b4412d00e7d63ba26051a5c53c2882308d3b14a731144ea57b9ddb5bf
  280308fe446589facc42f84507f75350372caeca6a5cc4533f271c8a16c46c332bc24363
  671721573cca17906d7e536c4bb3cb8734bc827a0e3d42bffbc4418537c9319b3d86d5ae
  b4916bb7750a519c9b0824aae7749c183613afba21be1c3844389d51a25032f01ac3a5ba
  003084d3f16cf753a8427932b2211ceb79c7f20387751b067933ba71acbdd3732479fb1f
  ac28034628a94b1a6637c1a21cf34743c96e363a3bbcb84fb6b397b948bc917267a8ec78
  7d498180804e00a0b985eb6bea071bc78383986352ddd471b73a6c9b395c77069921ac36
  f355941ec60b4000d03e113bda957960d329f7cc17d8f1ac7c9c4911f007af3ca1bb9904
  d3fc2d12ecc67db0b718a11bf0d730fc4a83b2a8655158ba72c8ab5bb77a509abc894304
  a6f1a8118b87e74b96af2766d3924f4a047441b1056df620a700c9506692544c07600928
  f8ba0e4379012e58ba594a4c70d65bab1402e6a546f885ac6e148899d92b46d02853e78d
  3b610ccda8bc19b23ff786bafab5c0b6dc730aacc540982fe292aeabf5467d0a76b7a010
  854ac53fd2c96cc5605a85511064ae4c37c2e6206709f17e7ba03eada024cc1673204740
  5a36849f839ddd3b82bbd3156a9741691c7c5d0a128ec0414b8292a7458ee8e9cce3323a
  16bca3f70a29fc82cde95857483cce624251e85979b97882b216a09de3b7b3546384a3cb
  1f29a485cb61d733b5e62a0631f21703617587a77d9e95505b88bc79152d44b76a31e769
  df48c4b0b8bcda105897330fa49570256214fdb7a0101a775a732f46301ebde75271f235
  9fc62017c24d7ef95d7e717a42c5413d79030f466c64bc26414b9e30b19e4e68b2616209
  e3eccad2d14a5b732f95b3bc769971e216359c3a2b947222b52cc54aabcfa7c04e82b799
  5c049d84ac82a9c56c7c3b05be030ea33902c6f984b20c5759f8c3b5d081442860c85874
  6f22a632017efcf59d90c32e24b7022944bfe8d038ff0cad385230f79aaebd1c344cb726
  57733dc80879dbd084724c37c44c2cdf976993ea5d0bc644d1bc8c52c00b7ddcab0f7633
  ea6aa728cb0c979a1cee7c2c50b84fc32a94355accb139484fc814e78018cf75b10d50ac
  7c9405a8e86ca56a38c5fb1730e53dc6d2ae3c768c855b0998049b86d88e5321145a4359
  d37c308ea2c46a962b20006fa1d3a2f1c511ae807a1fa085c2988095132209270a81d545
  cf36a6aaa564b729918af4cc14191075cc523320bf7f4ac4c2b08552b093ac8137f62c60
  7be70cdc373dab2b107cbaa7833629b7115210aa165fdc7858989346409303b88c827202
  39233a9583c426919d96796dc7982f73d3ca0cc73a0a5cc65ac608f6d008a2823d54b62d
  6296a6df8284a1733b327807ff3a7726c5059102a8266299ea19ce46254ecd626646cc3e
  50a73773e6927d116633008188d97b891867d689c2e98cb50354806bca34448940ae8b56
  4ef2800d7c9060c905e8718d90276bad3b48058b9600181f62f0c27c95b85baacbf2bb51
  82524766903d39e3b10b35b6a8c1155d41862897353087ce73b16a12cb302b3c2cf09048
  7d45461ad327caf77b2f868a6eb898fb78ccda26ac0e7184bf874d9eb8ba9708b06471af
  9a207a8fa4407612cf6a589ad9c55c8a3569337101b5b9c2ee60a8ca6bb92e0ab4ba763f
  f3686710011ec420b8545a555c78cadc3baa732ac8d7a89915739281ab10a290a7ee70b3
  e58a2305197866f49e82504923a38206c3adba35989fc00f1ed7a2e12b17d1e212a74bb2
  b746955c9749f7808178c63c86c060d833739c156afa0300afa61abd028fbbf9311b154f
  7f691f4326976b66c475ebc9a4fc91ac93c9d26588de14455205015606181146cd734c55
  b3ac583a05495e902ff2d3376034c0e66796f6003d685b53b8f0853bb147ad15b6fe0caa
  1bfb6119737313a5b603a28cf2905bf7917c16561d5f425d9f10bca9c0bf9118c3c19562
  01461f1b3ca4f36c4aaa963a657b092d123daf65ba4763b8fbc204490c121238c4f7544c
  a10185b131c2cdd7b700d36b7ac39642759952fa6b0e94b19b18625f194f16594d031352
  97b759c396c20c8961f5880de2b8469c94a917090f01088eedb79ede6092b9a4bf703216
  b5ecbfb328204269184b5ac83317601d1531c246cd2a7c1cc9114d8fcb496d5ac3add629
  339a2cc0f13e29ecce75589b92e9123a56b0ec90ac35c5b5bd71bbce6237d317b55d19a0
  ee3096b0390f8f005c51186d876b9a54ca6bfb6595b467b7ec00962ec802394c904dc3a5
  e223b858dbc58f69066eb46d8cc58e776456e3300c070b666e4c5b73c68a7984533b804c
  77714154158ae347b22e7962b668c0fd316d3164272d051cf54aa9c408b17ea1cfabeb01
  83671e10f294810ab46ad0c8fc53c58e9007f5a7b9bd36949fc10d62b34fc2a8c9504c5b
  b6936c018bbb623c6d10429b0668a20b0706f5a2ad9ac265af11adadb4955a5059bb688f
  f52911d5e645e98c5bbbc086740199cc6b48a41a6d006a644e3232092504f4fc34516773
  2cb1a391749dc6654b8c4bc6c14a0c20f134fd84a3a9c6652c27867ce8ccfab14f6a1201
  838ba86a068be845181ef19dfb7bc92e5185e3b07ff1482da619c47e887d6e0a9f47455d
  8068257b16bdc919ab12f33ed709170b25237a36c2052390af5c1588715a98b89abdcb5b
  16376a1cc2234087b5e7f7cc91b6b86854a7d9a0b7c040910cf04604221f92e18c364422
  a8ba5564db4cd0d20468e7cd93c9a7fb86605243b672f92070e7af40c6966a329a2e8a6e
  eb128e89476fd0a93c4d5b20022b7f115226f2e301ece83225834091647e25050a55cb3e
  73cc1f16db321e019d71c6c96d0b95c0b34e919761a037867cd0a8cfb20f60ca3166da8c
  895a1afc07cd85c06d846644be7a788cb0711a519812427ef8994693750867d41f4c7aae
  d657b933864dd683aa06d584daa54b92f399c3137c97e07c2e005ccf3c2be37286200377
  7ef715dd0978b86514063c0334b58398979953c7694e2170195c4a5ad85943477597f600
  959a4da39720145ccbf1b53642f2347442ca2f600da10d273197795c863e8abc442aa9f5
  656a6cdc0f1f45551b92ed65e02500e91956cf19f97fad2fbe77d62990ae8546d2c0b81d
  61969a84dd4020496c11c3865783e44275f3247461bd7d92b707ac24aeada15587f75f5f
  66ee5bef8973f58d752cc334508f5130dda261ec
pk
  50a73773e6927d116633008188d97b891867d689c2e98cb50354806bca34448940ae8b56
  4ef2800d7c9060c905e8718d90276bad3b48058b9600181f62f0c27c95b85baacbf2bb51
  82524766903d39e3b10b35b6a8c1155d41862897353087ce73b16a12cb302b3c2cf09048
  7d45461ad327caf77b2f868a6eb898fb78ccda26ac0e7184bf874d9eb8ba9708b06471af
  9a207a8fa4407612cf6a589ad9c55c8a3569337101b5b9c2ee60a8ca6bb92e0ab4ba763f
  f3686710011ec420b8545a555c78cadc3baa732ac8d7a89915739281ab10a290a7ee70b3
  e58a2305197866f49e82504923a38206c3adba35989fc00f1ed7a2e12b17d1e212a74bb2
  b746955c9749f7808178c63c86c060d833739c156afa0300afa61abd028fbbf9311b154f
  7f691f4326976b66c475ebc9a4fc91ac93c9d26588de14455205015606181146cd734c55
  b3ac583a05495e902ff2d3376034c0e66796f6003d685b53b8f0853bb147ad15b6fe0caa
  1bfb6119737313a5b603a28cf2905bf7917c16561d5f425d9f10bca9c0bf9118c3c19562
  01461f1b3ca4f36c4aaa963a657b092d123daf65ba4763b8fbc204490c121238c4f7544c
  a10185b131c2cdd7b700d36b7ac39642759952fa6b0e94b19b18625f194f16594d031352
  97b759c396c20c8961f5880de2b8469c94a917090f01088eedb79ede6092b9a4bf703216
  b5ecbfb328204269184b5ac83317601d1531c246cd2a7c1cc9114d8fcb496d5ac3add629
  339a2cc0f13e29ecce75589b92e9123a56b0ec90ac35c5b5bd71bbce6237d317b55d19a0
  ee3096b0390f8f005c51186d876b9a54ca6bfb6595b467b7ec00962ec802394c904dc3a5
  e223b858dbc58f69066eb46d8cc58e776456e3300c070b666e4c5b73c68a7984533b804c
  77714154158ae347b22e7962b668c0fd316d3164272d051cf54aa9c408b17ea1cfabeb01
  83671e10f294810ab46ad0c8fc53c58e9007f5a7b9bd36949fc10d62b34fc2a8c9504c5b
  b6936c018bbb623c6d10429b0668a20b0706f5a2ad9ac265af11adadb4955a5059bb688f
  f52911d5e645e98c5bbbc086740199cc6b48a41a6d006a644e3232092504f4fc34516773
  2cb1a391749dc6654b8c4bc6c14a0c20f134fd84a3a9c6652c27867ce8ccfab14f6a1201
  838ba86a068be845181ef19dfb7bc92e5185e3b07ff1482da619c47e887d6e0a9f47455d
  8068257b16bdc919ab12f33ed709170b25237a36c2052390af5c1588715a98b89abdcb5b
  16376a1cc2234087b5e7f7cc91b6b86854a7d9a0b7c040910cf04604221f92e18c364422
  a8ba5564db4cd0d20468e7cd93c9a7fb86605243b672f92070e7af40c6966a329a2e8a6e
  eb128e89476fd0a93c4d5b20022b7f115226f2e301ece83225834091647e25050a55cb3e
  73cc1f16db321e019d71c6c96d0b95c0b34e919761a037867cd0a8cfb20f60ca3166da8c
  895a1afc07cd85c06d846644be7a788cb0711a519812427ef8994693750867d41f4c7aae
  d657b933864dd683aa06d584daa54b92f399c3137c97e07c2e005ccf3c2be37286200377
  7ef715dd0978b86514063c0334b58398979953c7694e2170195c4a5ad85943477597f600
  959a4da39720145ccbf1b53642f2347442ca2f600da10d273197795c863e8abcfa8df7f0
  5b46a2407f64154a3fdabb9cb29823a51230381c0cf5645dbd83e537
eseed  badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea
ct
  728c80ddcb9ee7fe732dd3847c18a06a25049b2deb488ed770de9cb5a8585d6d7a68ed3f
  fbda47b583c3edcc963ea9d5fc3c26f2b7a4d4d0eabe191e0202950d4293bc3f4d48eccb
  233d6443188eb30a8682d6cd5b7c762b9dc5d0a144d8b6af9f16f7929bd5bab1f66747b5
  cfc39d8c6d46e4fd0b3f084b073797dc35a9de67be99a97bb3328157e34d249c20b97569
  4e825b130960c8c0eefc0f631522783821ab8c4a07a0d2d9318ae5590e187abe7319cc44
  7823c6aa5ac093fe724d30a6a813e82447a7b1dba8b44f8972b1cf9f1fcc22500e63af95
  cfe73996a25a4f1476dc80b76a06247b19a408909dba5e7cd029de97d1848567c6aceff2
  0649c8df0ff8f7c65490d2916b323845c37b2055689200f09216bc87b49ae1a48ec3679b
  8ab09029a5484a859790913cf36f827bcdf620a2603ef151fe7748adbd0c94c8917e7c7c
  282f345d46914136fd72a3d1518e693406a202512bd062ebccd5d9c851941ca5502d8cfe
  b6eb19e8ec80b8000677ecc52fb7e2d95be2725dfa836224ec0d3c8dd89f9ba4bff789c6
  f39316deac98a045a748c05607e11a24b96f5a530e5cfcddc0213731f907f1d77dca86e9
  96f3139d974a8dd2d3d0e14e178ae7235e0b6901f26f8655e5ce451df6d494adc0a13e21
  e0744ce2f6cc85d38d7d31f6970236273cb4d1a97f53c1a36edb1c70799df5dfb5525c15
  09b2d2991532ec50f0571155a64b219050a5a2893d3ff9c13361922d9a3e29ff08e8d672
  52fe70d2f7fce6684722ae19a60a5de1ca5f0f680d33bb452122bf8d37bee7d034863e4d
  1f03cdcbe17f5ffecc4743415e1e71162c860cd0871b8c38ddf4dba5945641108948212c
  97d35a2fc92daa148d32e716847889107da209d772792d8a33477b547511964d2ef12ecb
  a5316fd92959cc42777289689bd6dec3fa152c820d94987208b235253397e670ecd6d311
  d7e0f799fdd29ca7a86178fdacf4e6dd8d4248c520886437dd1d47248c2b47aa15521d52
  703d87308da4c14d0e6aa0295d016c1c8296e04465ad3bfb1328723b4b6543e9899a0723
  484fb8b5b188954f2b5f45fd6af590082b2411dfea75b1735915f6140e03948d27c5c355
  b7126eae22a432b5c33e0360389f40fbebaed52438a9882ae5cffa4ce983982078762b35
  18ab1983f7a5f025a497b82e7d93d8ae17ea47dcbdb817656bdd0e9e00b2a48fb48eecd8
  e190b568b1039742faccf9d1ff15eb296d26d7aea289ea8e9bd05294059e9dbf1b81ed0c
  4f1ab74baed4dbdab44c35fb2d783320e1b2556705e9984c6f6c29b2416a09da7cb472d1
  7865fa6aa350f6a64b382b9e4d1b446307be3432b01593bf5635f0bf264557b3f5bfd15b
  f445cf3d5956780028014a968e647b960ddeae035877788ace5ef0c738c868d39bd49557
  77a1090a6d53902ffa807fba0848aa2add922987c6cce3635e6fab449e3bbc7ce5c22ffb
  451b5f218f336e64aacb992bf6c9230780628700b65da59c9da1bb15b2188b12a70552ca
  ee593941d4576c7b42cb39460ceef78d433a350ddaf337c9e3cdb25c4c9c271bd460d691
  cd4ceb76
ss     3ad2909dd15fbf86cad4fbf3c804a0d617d55bcff606db3f8cf446d06944a4d7

seed   17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef
sk
  8a670587c896b7f76c7425243c93b293265238215ca05a54cad28289013d4ddc153641b3
  c1229af052afb7c8c4d2a752ca52c15b2a91ae654168fcb6e4a2bb5be9611ce99c87b757
  4b1824ec4435b9c9c8996666a0b907bcb39fe4900f3675c5771528af5aae13b1a9cec0c2
  2e3503c73009205c455da314437b54cad4b8ccc8334054c39b093456bb51b916b81dfbb3
  6c518c1848a6575867a655b6085931cb0b7df06b564bc224e20c1ca0f8b9ff3ac2787309
  b7fb098ea2352e035cbe8984f2e73c64931da8993600fb423f6195670547510140927527
  898c8f4317799f8b592ea6c23856884cfb6460b643b9050a18440e268931f8631af48219
  82a72245768be3351c41a292577896d843b2a38c8b5ec19a398763364b7a9b17229db351
  3a83cbf8040eef143681174fcb192e6ab403b1c851af7202ebc3481fe2b479b2afc06932
  50256ace013b21d71117035012d2118c1687824c1e172706cf54bcbcf51bc3103b71e925
  a92406071c3886a6c50d7027c6acc3f8d10196371818d350afb61689877eb5c6210c4052
  821574f94b81d39411e7017ed64b8052997ac1517aace4ae418c2d4474a1719773d86953
  dbe36cf2a34fdec275e075961c7297629203cfb44c15c70bcc7cb51ba4002c80363477b8
  f87058ebb947cb991a25354894c71bb80c72f60824d0b2952000a91794b670eca7f127b3
  d0689e2802820c1abba910c6161c61c722be1da6b85b800c8c08aff7206b12c4b4308bac
  ac2b83c2117902f234d1349d38d77c838c01a4867fd3a118091356d9f301e3e95dbe674e
  b9f1a3f6a58b238355c19b229d86b6d26b21c7e1b064ecb5b5907d89a9c91b7b0c51072f
  3f00177a00b6a7282cb49172cec8afdeb74a222b7ffac1a3c5517ab11aa7661bc33321cf
  c0a5cd25d65eebd42edf255cc3a866e344a7cd4a553b3b5edc0584dd8364be414df987bd
  5b83cdf9c74688e1b3e2bccfde2a7a75b32d216a170c24c5c8c61c10840bb2cac7877a38
  1625846787079c516c7b7117766cb2d2372e434841f1237a5968ba0db43bf6251690331a
  c9721ff47b497d5a282b3a43199618e67a5d131993f3c21803877dea8390d6328e7dfc06
  33098cec671884b19a25b6b12e78983619209ba2a746f29a6c732460c41d82361afeb4ca
  47819f7aa563ec84c7be424402e76ed1339773e14323c3457e8c4c4f9075a540064a5c91
  aa937be2558d140c882391761fb371b2916ef010bd0566cad82a9281e015d7a95ed33505
  0bb2571e505f90bba22a50b7913104158464d1b8488fb07ec86a4db0154741725b45e542
  16d9b29ad79015caa96d16380732bf34021a6925cce3a3161ebbb573e96e142ba651e6a8
  e9c86c64c513fd77440c9717b448797f4932fbcba3f8fc9cec2402e246baec52332af83e
  49a0148f996026e9a017a7191f3a9c02f910cc990b094a86168a0959fb1e4ac2c0fde39d
  1ec2c2514c6807e6bb0e1b9497e79388dbb02951543b12766697ae4cd83dd6383cb6ac06
  f3316d65a287834b1eddf82cea7621dec27a2fbca283182022e945d5a8114480ae389716
  f8a45a35494eb6b67a9aa62afca2862da83789faaf9ae93afd86447f809b41656adefb7c
  fe109c456908ebe9490a37546045939dc8567eb804f3f3c9a0656013c2a559294301d01f
  88f47df80bc18b001922f99d64255dbb8a804352badccc905217af828a47d62272b5f40d
  09c46852dc0337b545eebb4423f792288119ca463a9d1bbf078509261c970533cb1169cf
  c21b96b79b48164cc6eeb0abe4cc687902b7d6a40939e9a02792c97f665f9f7281bbaa78
  0aa697ee2b096a6aa38ee082ef2356cae874f5f9126fdc93cc7499ee6838b24a267d437a
  c730ceeac12cbe131a0dc470b6e73843aa09ff3a9676caaa1f65bd5396c5b97a9d5d97cd
  063455f4a2a454f63f7990bdd6049f994595e7e6662d04af84346a4ae02352d1bf549902
  40aac170d20f8ef2861461aca80b121df502f41023ed1a44b0d76dcde4bc4ef82b8a6020
  3ea41879e96d8b74962180b34758acdf033bcf7856724994f7696717225ea32148289b88
  f10c6d814b202f145c38ca961e076e77d390b8e2a7eec81ed1a0c03f214371847f77ca9b
  4df31ceb97144f82a04d582760a0c5cf9778dee0a6ceb0a1399a1af5eb7035355221927a
  1d0c913d9083e81b7876b12750c6b78f052abff2729d307d4c9a06a7586c224520e046c2
  134bc25b41cf7ca03147174c5b9746be9b4decc600e990ab1323791a08b919d4cafbe3be
  a2d07dd640088bb329e7686e8c79c20017cec95a1fcacb7bfe67b76ac111068a5d3ba5a1
  84ac89ab364502c9096b3716a3e99bc891919d3621c5610a5735048b88b8bfc25d62608d
  810430b283a7c2129611450a8f9196d17c8575357910630c36492b8e38c5a4a56a04e15a
  a3072b3ea789d8510eeef45a16460cdf4a2c2ac5a1c6264a0a4cbe15aa0c70a89abc339b
  da172d315b9a800874063b9412504e844b42b2449d55f894b5a216ee8a6ed4bb05da8374
  1f4c4223637ded78be718b2c0ed10236f3c21130337d13851ee4c49ed3cebab356b4555e
  74f643c37586ff49c9722562f6fbad7f76ca5b3a955886ae9b758ae2c831a67178f3052f
  d7c8b71e509b5090925f07c8717620ec8b2f1378c206705ebe57b52ffb6ffde897681299
  833472d3c556f4f326e4e57159f04d3b0b3a9d1a5d06ecadce758a2fb1b4fb7a157b667a
  ad58a91475948b9934dee63d0459a64913a3b9a71f02b7380702550cc140093024697a88
  23f2954288bbec98147b1ab104b71731012fc19aaaf5c854e32b65ff714f4a395b8f795e
  b3f015df918d3f14c5514427f1c5c544017d57c17ae08767396c0ed3035935681245079b
  32240af29943bb72c7b4b4096075c767f1a4ce30a72df52784bc0ad2d49831a1c5378a1c
  3a2860321a5c06c276609a0593160422a96fbe21720a3b20b652a14f3939dbb9834a783c
  e9f9ad3b1c7347f37780eaccd0a004040a5ef7b8ccb1a50a3fb0bc0429307543307049aa
  3196116c576668d97b7ef6c69a6c7e94247ce4bc3615307e30547e5a2c927b38c7b71a59
  a7803a5f134886320e14fb6dbe62a525db667c654bfba9900e3127ab361a7e4653308202
  d6a63f36d1948c5b8c8ea51af673709ca08e97678c16a38b5b14a213f0c91523ae57f133
  4a138b22a620f1b5986c5bacdcb002822b3502f077de3a3fb09c5f43a1cf06cc2c13a07f
  8d4e94cf16820b4b1f7c979ce956405ab99706b6afd7090aeb7baff643eecf46fef06901
  9a9c95cf9d6d6165f8e09c94aee8ea6d375523f7c570fc99c114b54e4f5d13748428262b
  3e86ae2f91bccd03c1dc9e8d73bc4a097fc853261bd59151ea9fe285be98af980977bcf3
  cfd0ddd30e3729d42f2c10887444b1c274ef1710
pk
  fe109c456908ebe9490a37546045939dc8567eb804f3f3c9a0656013c2a559294301d01f
  88f47df80bc18b001922f99d64255dbb8a804352badccc905217af828a47d62272b5f40d
  09c46852dc0337b545eebb4423f792288119ca463a9d1bbf078509261c970533cb1169cf
  c21b96b79b48164cc6eeb0abe4cc687902b7d6a40939e9a02792c97f665f9f7281bbaa78
  0aa697ee2b096a6aa38ee082ef2356cae874f5f9126fdc93cc7499ee6838b24a267d437a
  c730ceeac12cbe131a0dc470b6e73843aa09ff3a9676caaa1f65bd5396c5b97a9d5d97cd
  063455f4a2a454f63f7990bdd6049f994595e7e6662d04af84346a4ae02352d1bf549902
  40aac170d20f8ef2861461aca80b121df502f41023ed1a44b0d76dcde4bc4ef82b8a6020
  3ea41879e96d8b74962180b34758acdf033bcf7856724994f7696717225ea32148289b88
  f10c6d814b202f145c38ca961e076e77d390b8e2a7eec81ed1a0c03f214371847f77ca9b
  4df31ceb97144f82a04d582760a0c5cf9778dee0a6ceb0a1399a1af5eb7035355221927a
  1d0c913d9083e81b7876b12750c6b78f052abff2729d307d4c9a06a7586c224520e046c2
  134bc25b41cf7ca03147174c5b9746be9b4decc600e990ab1323791a08b919d4cafbe3be
  a2d07dd640088bb329e7686e8c79c20017cec95a1fcacb7bfe67b76ac111068a5d3ba5a1
  84ac89ab364502c9096b3716a3e99bc891919d3621c5610a5735048b88b8bfc25d62608d
  810430b283a7c2129611450a8f9196d17c8575357910630c36492b8e38c5a4a56a04e15a
  a3072b3ea789d8510eeef45a16460cdf4a2c2ac5a1c6264a0a4cbe15aa0c70a89abc339b
  da172d315b9a800874063b9412504e844b42b2449d55f894b5a216ee8a6ed4bb05da8374
  1f4c4223637ded78be718b2c0ed10236f3c21130337d13851ee4c49ed3cebab356b4555e
  74f643c37586ff49c9722562f6fbad7f76ca5b3a955886ae9b758ae2c831a67178f3052f
  d7c8b71e509b5090925f07c8717620ec8b2f1378c206705ebe57b52ffb6ffde897681299
  833472d3c556f4f326e4e57159f04d3b0b3a9d1a5d06ecadce758a2fb1b4fb7a157b667a
  ad58a91475948b9934dee63d0459a64913a3b9a71f02b7380702550cc140093024697a88
  23f2954288bbec98147b1ab104b71731012fc19aaaf5c854e32b65ff714f4a395b8f795e
  b3f015df918d3f14c5514427f1c5c544017d57c17ae08767396c0ed3035935681245079b
  32240af29943bb72c7b4b4096075c767f1a4ce30a72df52784bc0ad2d49831a1c5378a1c
  3a2860321a5c06c276609a0593160422a96fbe21720a3b20b652a14f3939dbb9834a783c
  e9f9ad3b1c7347f37780eaccd0a004040a5ef7b8ccb1a50a3fb0bc0429307543307049aa
  3196116c576668d97b7ef6c69a6c7e94247ce4bc3615307e30547e5a2c927b38c7b71a59
  a7803a5f134886320e14fb6dbe62a525db667c654bfba9900e3127ab361a7e4653308202
  d6a63f36d1948c5b8c8ea51af673709ca08e97678c16a38b5b14a213f0c91523ae57f133
  4a138b22a620f1b5986c5bacdcb002822b3502f077de3a3fb09c5f43a1cf06cc2c13a07f
  8d4e94cf16820b4b1f7c979ce956405ab99706b6afd7090aeb7baff643eecf4662e83da2
  3b00014e75c63476b4ee1fb68c41b0fd8e16ee07affe5f7560039d0b
eseed  aee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d
ct
  bcf2bedcf8a0adfde648dac0ee5b430245fb8503c3c4ea15ba7e8c161c4fe124dbdae77c
  cf03b037b02da33779b765a5c7b1bf088a122c2e67b51df23dba59b93d802e23fc84b50c
  1007a6397e7808b49628339c9b45feee065602d673e6c666f86fba2725aae17647e40fef
  8cd5b8b348a90b49890ddb593fc69cf14a385b34a34a336aed92c4bb7b321f8ea43d934d
  e179b681cd180b7a98688184789ac21b3c2fb93e4d5e39ba4cd5ed0c53b5f509b1c8e066
  efedba4b25aac8ae0474b74d9e5771e689b8cc4018f19e75acf6a58017266d1b6ae4edfe
  a5cc8fc3bd9827c647439fcf84eef86e9da5801a0fe49e05c3a28c2b444fcdb323ba40f5
  04ffc329acd10956dec19331318b3518e149bb2a5d4445dc95942fb01543c296e43e0e45
  8d771a554ffe0869baa95ea16c2ffc19ee6540e3030bba4058cac2438365c6733a0f0fdf
  28df0a8e9f63c4813c0db4af0412bbe53996047be50c6ebf881cc3ec66c7440a49667056
  bcaf70092002e6be151029c3e718b32ac028e1e665289036ced742bb587d0a16e761239b
  d63a0ed11ae20f74599f2a9fabb9a36635b11951f465b2dffda2585029a2f565ded9ef5e
  0aab815020f046aa614d0e662a8e913f49ab022239d782754207f646046ddce2d1cda3c2
  69542640d389493dc0ab81197f48ed83616a51628bbf402c2fe57ec75a3b5ce78b52135f
  4b37affa764e9026adf0ff877f262cda47c13b18681b03937e56dc96862d1f7b034b456b
  ca175d0ec92fce18cbb531faa1e9a60d69222e53f6e3779cf18dacc763947f2d73349568
  e085667209eac5236df564051ce7dc7534d172560ed48d2ea616dc9d3a7466abe4508884
  97a22d5c9241a40f2c030ce5afb678237beb720c69e9ed45bbefc4366dcfeab03eb4307c
  506c853d23be752f9662609b6e82abaa948403510bd409327369d3f8e7d65673be08224a
  17a7602676ceecfb8bfc0bfcf6359bbb1ec36608fac43ba13356c485755ad67543c6f97d
  ee1e8912e47f47902c67f03901364b05b7706632ec728111bce05ecb23f4ca0b3e4c3aec
  f105bf7a8fb8238b817e20989d4291c8d469bea60377bea87c852b9c2659bd3ef62543f0
  d8fa67bd1d20786404b8e19a313a44cd6a9384df6b93f9239fe6e9b5fcd5fa97fa54197f
  0be845b64c4d8ebc8fef8ea5066809a0cbe3b1cbacb92a20bf8ee1ef647d9a0016e1013a
  6ed00e3dbebfe018c9cbc391e6f8bd81cd14f1a270acf4bcce3b0c4b7d63dd369422a765
  3d7f374d9e3af2c7f2a7c698fc41859d4f1856e229f10ee7767985207dec9a5bec39f3f5
  28ff1a5a9339fe57dce3041c62f5706e30a706a4a68ae89f002112d514edd8cbb542e984
  dfaa8fc5c469ba73fecb9b53eef2bc02b9e2aec250c494cc739fca2f6febe5d708643472
  1ed515b715979cd8d87dc101f87c04a7b396a251bd2b1b306b7dcebb9009ad3e50f9e147
  a100ca219027b590d57068a2035d11730992a1c26f3b54ca5690a3ec645287b003adb69c
  e1d5fe6faa73055864e1453c4adc1455586c4d7a33672bb96bfe5413b56e9b2b8b7357ba
  7bcc9c4d
ss     663e7206c595ac79c3710233356d344b2b198351a8d8d89effa6c9d9f54fb9f0
~~~

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
