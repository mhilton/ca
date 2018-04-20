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
	crtFile = flag.String("cert", "", "`file` containing the signing certificate. (required)")
	keyFile = flag.String("key", "", "`file` containing the signing key. (required)")
	csrFile = flag.String("req", "", "`file` containing the certificate request. (required)")
)

func main() {
	flag.Usage = cmd.Usage("usage: %s -cert file -key file -req file [options]", os.Args[0])
	flag.Parse()
	if *crtFile == "" {
		cmd.Usagef("no certificate file specified.")
	}
	if *keyFile == "" {
		cmd.Usagef("no key file specified.")
	}
	if *csrFile == "" {
		cmd.Usagef("no certificate signing request file specified.")
	}

	parent, err := ca.ReadCertificateFile(*crtFile)
	if err != nil {
		cmd.Fatalf(err, "cannot load signing certificate")
	}
	key, err := ca.ReadKeyFile(context.Background(), *keyFile, passphrase.Getter())
	if err != nil {
		cmd.Fatalf(err, "cannot load signing key")
	}
	csr, err := ca.ReadCertificateRequestFile(*csrFile)
	if err != nil {
		cmd.Fatalf(err, "cannot load certificate signing request")
	}

	if err := csr.CheckSignature(); err != nil {
		cmd.Fatalf(err, "invalid certificate signing request")
	}

	template := x509.Certificate{
		Subject:        subject.Subject(),
		DNSNames:       subject.DNSNames(),
		EmailAddresses: subject.EmailAddresses(),
		IPAddresses:    subject.IPAddresses(),
	}
	params.SetParams(&template)
	crt, err := ca.SignCertificate(csr, &template, parent, key)
	if err != nil {
		cmd.Fatalf(err, "cannot sign certificate")
	}
	if err := ca.WriteCertificate(os.Stdout, crt); err != nil {
		cmd.Fatalf(err, "cannot write certificate")
	}
}
