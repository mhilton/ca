package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"os"

	errgo "gopkg.in/errgo.v1"
)

func ReadCertificateRequestFile(path string) (*x509.CertificateRequest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errgo.Notef(err, "cannot open %s", path)
	}
	defer f.Close()
	csr, err := ReadCertificateRequest(f)
	if err != nil {
		return nil, errgo.Notef(err, "cannot read certificate signing request from %s", path)
	}
	return csr, nil
}

func ReadCertificateRequest(r io.Reader) (*x509.CertificateRequest, error) {
	b, err := ReadPEM(r)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	csr, err := UnmarshalCertificateRequest(b)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return csr, nil
}

func UnmarshalCertificateRequest(b *pem.Block) (*x509.CertificateRequest, error) {
	if b.Type != "CERTIFICATE REQUEST" {
		return nil, errgo.Newf("unsupported certificate request type %q", b.Type)
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, errgo.Notef(err, "invalid certificate request")
	}
	return csr, nil
}

func MarshalCertificateRequest(csr *x509.CertificateRequest) (*pem.Block, error) {
	if csr.Raw == nil {
		return nil, errgo.New("invalid certificate signing request")
	}
	return &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}, nil
}

func WriteCertificateRequest(w io.Writer, csr *x509.CertificateRequest) error {
	b, err := MarshalCertificateRequest(csr)
	if err != nil {
		return errgo.Mask(err)
	}
	return WritePEM(w, b)
}

func ReadCertificateFile(path string) (*x509.Certificate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errgo.Notef(err, "cannot open %s", path)
	}
	defer f.Close()
	crt, err := ReadCertificate(f)
	if err != nil {
		return nil, errgo.Notef(err, "cannot read certificate from %s", path)
	}
	return crt, nil
}

func ReadCertificate(r io.Reader) (*x509.Certificate, error) {
	b, err := ReadPEM(r)
	if err != nil {
		return nil, err
	}
	crt, err := UnmarshalCertificate(b)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return crt, nil
}

func UnmarshalCertificate(b *pem.Block) (*x509.Certificate, error) {
	if b.Type != "CERTIFICATE" {
		return nil, errgo.Newf("unsupported certificate type %q", b.Type)
	}
	crt, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, errgo.Notef(err, "invalid certificate")
	}
	return crt, nil
}

func MarshalCertificate(crt *x509.Certificate) (*pem.Block, error) {
	if crt.Raw == nil {
		return nil, errgo.New("invalid certificate")
	}
	return &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt.Raw,
	}, nil
}

func WriteCertificate(w io.Writer, crt *x509.Certificate) error {
	b, err := MarshalCertificate(crt)
	if err != nil {
		return errgo.Mask(err)
	}
	return WritePEM(w, b)
}

func SelfSignCertificate(params *x509.Certificate, key crypto.Signer) (*x509.Certificate, error) {
	template := *params
	if err := generateCertificateValues(&template, key.Public()); err != nil {
		return nil, errgo.Mask(err)
	}

	data, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	crt, err := x509.ParseCertificate(data)
	if err != nil {
		// If we can't parse a certificate that we've just created something is very wrong.
		panic(err)
	}
	return crt, nil
}

func generateCertificateValues(template *x509.Certificate, publicKey interface{}) error {
	if template.SerialNumber == nil {
		max := big.NewInt(1)
		max.Lsh(max, 20*8)
		var err error
		template.SerialNumber, err = rand.Int(rand.Reader, max)
		if err != nil {
			return errgo.Notef(err, "cannot generate serial number")
		}
	}
	if template.SubjectKeyId == nil {
		data, err := x509.MarshalPKIXPublicKey(publicKey)
		if err == nil {
			sum := sha1.Sum(data)
			template.SubjectKeyId = sum[:]
		}
	}
	return nil
}

func SignCertificate(csr *x509.CertificateRequest, params, parent *x509.Certificate, key crypto.Signer) (*x509.Certificate, error) {
	template := *params
	if len(template.Subject.ToRDNSequence()) == 0 {
		template.Subject = csr.Subject
	}
	if len(template.DNSNames) == 0 {
		template.DNSNames = csr.DNSNames
	}
	if len(template.EmailAddresses) == 0 {
		template.EmailAddresses = csr.EmailAddresses
	}
	if len(template.IPAddresses) == 0 {
		template.IPAddresses = csr.IPAddresses
	}
	if err := generateCertificateValues(&template, csr.PublicKey); err != nil {
		return nil, errgo.Mask(err)
	}

	data, err := x509.CreateCertificate(rand.Reader, &template, parent, csr.PublicKey, key)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	crt, err := x509.ParseCertificate(data)
	if err != nil {
		// If we can't parse a certificate that we've just created something is very wrong.
		panic(err)
	}
	return crt, nil
}

func SignCertificateRequest(template *x509.CertificateRequest, key crypto.Signer) (*x509.CertificateRequest, error) {
	data, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	csr, err := x509.ParseCertificateRequest(data)
	if err != nil {
		// If we can't parse a certificate request that we've just created something is very wrong.
		panic(err)
	}
	return csr, nil
}
