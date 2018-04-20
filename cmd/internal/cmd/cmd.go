// Package cmd contains useful routines shared by commands.
package cmd

import (
	"flag"
	"fmt"
	"os"
)

func Fatalf(err error, msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg, args...)
	fmt.Fprintf(os.Stderr, ": %s\n", err)
	os.Exit(1)
}

func Usagef(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg, args...)
	os.Stderr.WriteString("\n")
	flag.Usage()
	os.Exit(2)
}

func Usage(format string, args ...interface{}) func() {
	usage := fmt.Sprintf(format, args...)
	return func() {
		fmt.Fprintln(os.Stderr, usage)
		flag.PrintDefaults()
	}
}