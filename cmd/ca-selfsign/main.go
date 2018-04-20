package main

import (
	"context"
	"crypto/x509"
	"flag"
	"os"

	"github.com/mhilton/ca"
	"github.com/mhilton/ca/cmd/internal/cmd"
	"github.com/mhilton/ca/cmd/internal/params"
	"github.com/mhilton/ca/cmd/internal/passphrase"
	"github.com/mhilton/ca/cmd/internal/subject"
)

var (
	keyFile = flag.String("key", "", "`file` containing the signing key. (required)")
)

func main() {
	flag.Usage = cmd.Usage("usage: %s -key file [options]", os.Args[0])
	flag.Parse()

	if *keyFile == "" {
		cmd.Usagef("key file required.")
	}
	key, err := ca.ReadKeyFile(context.Background(), *keyFile, passphrase.Getter())
	if err != nil {
		cmd.Fatalf(err, "cannot read key")
	}
	template := x509.Certificate{
		Subject:        subject.Subject(),
		DNSNames:       subject.DNSNames(),
		EmailAddresses: subject.EmailAddresses(),
		IPAddresses:    subject.IPAddresses(),
	}
	params.SetParams(&template)
	crt, err := ca.SelfSignCertificate(&template, key)
	if err != nil {
		cmd.Fatalf(err, "cannot create certificate")
	}
	if err := ca.WriteCertificate(os.Stdout, crt); err != nil {
		cmd.Fatalf(err, "cannot write certificate")
	}
}
