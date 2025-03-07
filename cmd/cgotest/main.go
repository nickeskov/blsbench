package main

import (
	"blsbench/bls/cbls"
)

func main() {
	// check compilation with and without CGO
	const (
		msg  = "hello world"
		sigN = 10
	)
	_, _, err := cbls.GenerateAggregatedSigCBLSKeyG1SigG2([]byte(msg), sigN)
	if err != nil {
		panic(err)
	}

	// doesn't work with disabled CGo
	/*
		_, _, err = pbls.GenerateAggregatedSigPrysmBLS([]byte(msg), sigN)
		if err != nil {
			panic(err)
		}
	*/
}
