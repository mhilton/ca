package passphrase

import (
	"context"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh/terminal"
	errgo "gopkg.in/errgo.v1"

	"github.com/mhilton/ca"
)

var (
	nopass     = flag.Bool("nopass", false, "disable requesting a passphrase interactively.")
	passphrase = flag.String("passphrase", "", "specify the passphrase to use.")
)

func Getter() ca.PassphraseGetter {
	if *passphrase != "" {
		return constPassphraseGetter{
			passphrase: []byte(*passphrase),
		}
	}
	if *nopass {
		return constPassphraseGetter{
			passphrase: nil,
		}
	}
	return interactivePassphraseGetter{}
}

type constPassphraseGetter struct {
	passphrase []byte
}

func (pg constPassphraseGetter) GetPassphrase(_ context.Context) ([]byte, error) {
	return pg.passphrase, nil
}

type interactivePassphraseGetter struct{}

func (interactivePassphraseGetter) GetPassphrase(_ context.Context) ([]byte, error) {
	f := os.Stdin
	if !terminal.IsTerminal(int(f.Fd())) {
		f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return nil, errgo.Notef(err, "cannot open terminal")
		}
		defer f.Close()
	}
	if _, err := fmt.Fprint(f, "Passphrase: "); err != nil {
		return nil, errgo.Notef(err, "cannot write to terminal")
	}
	pw, err := terminal.ReadPassword(int(f.Fd()))
	if err != nil {
		return nil, errgo.Notef(err, "cannot read passphrase")
	}
	return pw, nil
}
