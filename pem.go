package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"os"

	errgo "gopkg.in/errgo.v1"
)

type PassphraseGetter interface {
	GetPassphrase(ctx context.Context) ([]byte, error)
}

func ReadPEM(r io.Reader) (*pem.Block, error) {
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, errgo.New("invalid PEM data")
	}
	return block, nil
}

func ReadEncryptedPEM(ctx context.Context, r io.Reader, pg PassphraseGetter) (*pem.Block, error) {
	b, err := ReadPEM(r)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if !x509.IsEncryptedPEMBlock(b) {
		return b, nil
	}
	passphrase, err := pg.GetPassphrase(ctx)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	b.Bytes, err = x509.DecryptPEMBlock(b, passphrase)
	if err != nil {
		return nil, errgo.Notef(err, "cannot decode block")
	}
	return b, nil
}

func ReadPEMFile(path string) (*pem.Block, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errgo.Notef(err, "cannot open %s", path)
	}
	defer f.Close()
	b, err := ReadPEM(f)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return b, nil
}

func ReadEncryptedPEMFile(ctx context.Context, path string, pg PassphraseGetter) (*pem.Block, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errgo.Notef(err, "cannot open %s", path)
	}
	defer f.Close()
	b, err := ReadEncryptedPEM(ctx, f, pg)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	return b, nil
}

func WritePEM(w io.Writer, b *pem.Block) error {
	return errgo.Mask(pem.Encode(w, b))
}

func WriteEncryptedPEM(ctx context.Context, w io.Writer, b *pem.Block, pg PassphraseGetter, alg x509.PEMCipher) error {
	var passphrase []byte
	if alg != 0 && pg != nil {
		var err error
		passphrase, err = pg.GetPassphrase(ctx)
		if err != nil {
			return errgo.Mask(err, errgo.Any)
		}
	}
	if len(passphrase) > 0 {
		var err error
		b, err = x509.EncryptPEMBlock(rand.Reader, b.Type, b.Bytes, passphrase, alg)
		if err != nil {
			return errgo.Notef(err, "cannot encrypt block")
		}
	}
	return errgo.Mask(WritePEM(w, b))
}
