//go:generate go run generate.go
package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/cloudflare/circl/kem/xwing"
)

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type oneAsymmetricKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func main() {
	scheme := xwing.Scheme()
	var seed [32]byte // 000102…1e1f

	for i := 0; i < len(seed); i++ {
		seed[i] = byte(i)
	}

	pk, _ := scheme.DeriveKeyPair(seed[:])

	ppk, _ := pk.MarshalBinary()

	alg := pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62253, 25722},
	}

	apk := subjectPublicKeyInfo{
		Algorithm: alg,
		PublicKey: asn1.BitString{
			BitLength: len(ppk) * 8,
			Bytes:     ppk,
		},
	}

	ask := oneAsymmetricKey{
		Algorithm:  alg,
		PrivateKey: seed[:],
	}

	papk, err := asn1.Marshal(apk)
	if err != nil {
		panic(err)
	}

	pask, err := asn1.Marshal(ask)
	if err != nil {
		panic(err)
	}

	f, err := os.Create("xwing.pub")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if err = pem.Encode(f, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: papk,
	}); err != nil {
		panic(err)
	}

	f2, err := os.Create("xwing.priv")
	if err != nil {
		panic(err)
	}
	defer f2.Close()

	if err = pem.Encode(f2, &pem.Block{
		Type:  fmt.Sprintf("X-WING PRIVATE KEY"),
		Bytes: pask,
	}); err != nil {
		panic(err)
	}
}
