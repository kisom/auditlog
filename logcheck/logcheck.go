package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"hg.tyrfingr.is/kyle/auditlog"
)

func checkerr(err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "%v\n", err)
	os.Exit(1)
}

func public(in []byte) *ecdsa.PublicKey {
	pub, err := x509.ParsePKIXPublicKey(in)
	checkerr(err)

	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		err = errors.New("invalid public key")
		checkerr(err)
	}

	return pub.(*ecdsa.PublicKey)
}

func main() {
	keyFile := flag.String("k", "logger.pub", "logger's public key")
	flag.Parse()

	in, err := ioutil.ReadFile(*keyFile)
	checkerr(err)

	pub := public(in)

	for i, log := range flag.Args() {
		in, err = ioutil.ReadFile(log)
		checkerr(err)

		fmt.Printf("Verifying %s\n", log)
		cl, ok := auditlog.VerifyCertifiedLog(in, pub)
		if !ok {
			err = errors.New("failed to verified certified log")
			checkerr(err)
		}

		out, err := json.Marshal(cl)
		checkerr(err)

		buf := &bytes.Buffer{}
		err = json.Indent(buf, out, "", "    ")
		checkerr(err)

		filename := fmt.Sprintf("verified_logs_%d.json", i)
		fmt.Printf("Writing logs to %s\n", filename)
		err = ioutil.WriteFile(filename, buf.Bytes(), 0644)
	}
}
