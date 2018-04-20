package params

import (
	"crypto/x509"
	"flag"
	"math/big"
	"time"

	errgo "gopkg.in/errgo.v1"
)

var (
	days         = flag.Int("days", 30, "Number of `days` for which the certificate will be valid.")
	isCA         = flag.Bool("ca", false, "certificate can be used to sign other certificates.")
	maxPathLen   = flag.Int("max-path-len", -1, "maximum path `length` for certificates signed by this certificate (-1 implies no maximum)")
	notAfter     timeVar
	notBefore    timeVar
	serialNumber bigIntVar
)

func init() {
	flag.Var(&notAfter, "not-after", "`time` after which the certificate is invalid. (overrides -days)")
	flag.Var(&notBefore, "not-before", "`time` before which the certificate is invalid. (default now)")
	flag.Var(&serialNumber, "serial", "serial number to assign to the certificate.")
}

func SetParams(template *x509.Certificate) {
	template.SerialNumber = serialNumber.n
	template.NotBefore = time.Time(notBefore)
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now()
	}
	template.NotAfter = time.Time(notAfter)
	if template.NotAfter.IsZero() {
		template.NotAfter = template.NotBefore.Add(time.Duration(*days) * 24 * time.Hour)
	}
	template.BasicConstraintsValid = true
	template.IsCA = *isCA
	if *maxPathLen >= 0 {
		template.MaxPathLen = *maxPathLen
		template.MaxPathLenZero = template.MaxPathLen == 0
	}
}

type timeVar time.Time

func (v *timeVar) Set(s string) error {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return errgo.Notef(err, "cannot parse")
	}
	*v = timeVar(t)
	return nil
}

func (v timeVar) String() string {
	if time.Time(v).IsZero() {
		return ""
	}
	return time.Time(v).Format(time.RFC3339)
}

type bigIntVar struct {
	n *big.Int
}

func (v *bigIntVar) Set(s string) error {
	var ok bool
	v.n, ok = new(big.Int).SetString(s, 0)
	if !ok {
		return errgo.Newf("invalid number %q", s)
	}
	return nil
}

func (v bigIntVar) String() string {
	if v.n == nil {
		return ""
	}
	return "0x" + v.n.Text(16)
}
