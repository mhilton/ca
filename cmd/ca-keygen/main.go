package main

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"flag"
	"os"

	errgo "gopkg.in/errgo.v1"

	"github.com/mhilton/ca"
	"github.com/mhilton/ca/cmd/internal/cmd"
	"github.com/mhilton/ca/cmd/internal/passphrase"
)

var (
	bits    = flag.Int("bits", 2048, "`size` of key, for RSA.")
	cipher  = cipherVar("aes128")
	curve   = curveVar("p256")
	keyType = keyTypeVar("rsa")
)

func init() {
	flag.Var(&cipher, "cipher", "`cipher` to use to encode the generated key.")
	flag.Var(&curve, "curve", "name of the `curve`, for ECDSA.")
	flag.Var(&keyType, "type", "`type` of key (rsa or ecdsa).")
}

func main() {
	flag.Usage = cmd.Usage("%s [options]", os.Args[0])
	flag.Parse()

	key, err := keyType.generate()
	if err != nil {
		cmd.Fatalf(err, "error generating key")
	}
	if err = ca.WriteKey(context.Background(), os.Stdout, key, passphrase.Getter(), cipher.cipher()); err != nil {
		cmd.Fatalf(err, "error writing key")
	}
}

type curveVar string

var curves = map[string]func() elliptic.Curve{
	"p224": elliptic.P224,
	"p256": elliptic.P256,
	"p384": elliptic.P384,
	"p521": elliptic.P521,
}

func (v *curveVar) Set(s string) error {
	if _, ok := curves[s]; ok {
		*v = curveVar(s)
		return nil
	}
	return errgo.Newf("unsupported curve %q", s)
}

func (v curveVar) String() string {
	return string(v)
}

func (v curveVar) curve() elliptic.Curve {
	return curves[string(v)]()
}

type keyTypeVar string

var keyTypes = map[string]func() (crypto.Signer, error){
	"rsa": func() (crypto.Signer, error) {
		return ca.GenerateRSAKey(*bits)
	},
	"ecdsa": func() (crypto.Signer, error) {
		return ca.GenerateECDSAKey(curve.curve())
	},
}

func (v *keyTypeVar) Set(s string) error {
	if _, ok := keyTypes[s]; ok {
		*v = keyTypeVar(s)
		return nil
	}
	return errgo.Newf("unsupported key type %q", s)
}

func (v keyTypeVar) String() string {
	return string(v)
}

func (v keyTypeVar) generate() (crypto.Signer, error) {
	return keyTypes[string(v)]()
}

type cipherVar string

var ciphers = map[string]x509.PEMCipher{
	"":       0,
	"des":    x509.PEMCipherDES,
	"3des":   x509.PEMCipher3DES,
	"aes128": x509.PEMCipherAES128,
	"aes192": x509.PEMCipherAES192,
	"aes256": x509.PEMCipherAES192,
}

func (v *cipherVar) Set(s string) error {
	if _, ok := ciphers[s]; ok {
		*v = cipherVar(s)
		return nil
	}
	return errgo.Newf("unsupported cipher %q", s)
}

func (v cipherVar) String() string {
	return string(v)
}

func (v cipherVar) cipher() x509.PEMCipher {
	return ciphers[string(v)]
}
