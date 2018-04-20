package main

import (
	"context"
	"crypto/x509"
	"flag"
	"os"

	"github.com/mhilton/ca"
	"github.com/mhilton/ca/cmd/internal/cmd"
	"github.com/mhilton/ca/cmd/internal/passphrase"
	"github.com/mhilton/ca/cmd/internal/subject"
)

var (
	keyFile = flag.String("key", "", "`file` containing the signing key (required).")
)

func main() {
	flag.Usage = cmd.Usage("usage: %s -key file [options]", os.Args[0])
	flag.Parse()

	if *keyFile == "" {
		cmd.Usagef("no key file specified")
	}
	key, err := ca.ReadKeyFile(context.Background(), *keyFile, passphrase.Getter())
	if err != nil {
		cmd.Fatalf(err, "")
	}
	template := &x509.CertificateRequest{
		Subject:        subject.Subject(),
		DNSNames:       subject.DNSNames(),
		EmailAddresses: subject.EmailAddresses(),
		IPAddresses:    subject.IPAddresses(),
	}
	csr, err := ca.SignCertificateRequest(template, key)
	if err != nil {
		cmd.Fatalf(err, "cannot create certificate request")
	}
	if err := ca.WriteCertificateRequest(os.Stdout, csr); err != nil {
		cmd.Fatalf(err, "cannot write certificate request")
	}
}
