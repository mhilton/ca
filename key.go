package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"

	errgo "gopkg.in/errgo.v1"
)

func ReadKeyFile(ctx context.Context, path string, pg PassphraseGetter) (crypto.Signer, error) {
	b, err := ReadEncryptedPEMFile(ctx, path, pg)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	return UnmarshalKey(b)
}

func ReadKey(ctx context.Context, r io.Reader, pg PassphraseGetter) (crypto.Signer, error) {
	b, err := ReadEncryptedPEM(ctx, r, pg)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	return UnmarshalKey(b)
}

func UnmarshalKey(b *pem.Block) (crypto.Signer, error) {
	var key interface{}
	var err error
	switch b.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	default:
		return nil, errgo.Newf("unsupported key type %q", b.Type)
	}
	if err != nil {
		return nil, errgo.Notef(err, "invalid key")
	}
	return key.(crypto.Signer), nil
}

func MarshalKey(key crypto.Signer) (*pem.Block, error) {
	b := new(pem.Block)
	switch v := key.(type) {
	case (*rsa.PrivateKey):
		b.Type = "RSA PRIVATE KEY"
		b.Bytes = x509.MarshalPKCS1PrivateKey(v)
	case (*ecdsa.PrivateKey):
		b.Type = "EC PRIVATE KEY"
		var err error
		b.Bytes, err = x509.MarshalECPrivateKey(v)
		if err != nil {
			return nil, errgo.Notef(err, "cannot marshal key")
		}
	default:
		return nil, errgo.Newf("unsupported key type %T", key)
	}
	return b, nil
}

func WriteKey(ctx context.Context, w io.Writer, key crypto.Signer, pg PassphraseGetter, alg x509.PEMCipher) error {
	b, err := MarshalKey(key)
	if err != nil {
		return errgo.Mask(err)
	}
	return WriteEncryptedPEM(ctx, w, b, pg, alg)
}

func GenerateRSAKey(bits int) (crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	return key, errgo.Mask(err)
}

func GenerateECDSAKey(curve elliptic.Curve) (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	return key, errgo.Mask(err)
}
