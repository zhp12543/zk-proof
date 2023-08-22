// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package proof

import (
	"context"
	"errors"
	"fmt"
	"github.com/zhp12543/zk-proof/curve"
	"github.com/zhp12543/zk-proof/paillier"
	"github.com/zhp12543/zk-proof/prime"
	"math/big"
	"runtime"
	"time"
)

const (
	// Using a modulus length of 2048 is recommended in the GG18 spec
	paillierModulusLen = 2048
	// Two 1024-bit safe primes to produce NTilde
	safePrimeBitLen = 1024
	// Ticker for printing log statements while generating primes/modulus
	logProgressTickInterval = 8 * time.Second
)

// GeneratePreParams finds two safe primes and computes the Paillier secret required for the protocol.
// This can be a time consuming process so it is recommended to do it out-of-band.
// If not specified, a concurrency value equal to the number of available CPU cores will be used.
// If pre-parameters could not be generated before the timeout, an error is returned.
func GeneratePreParams(timeout time.Duration, optionalConcurrency ...int) (*PaillierParams, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return GeneratePreParamsWithContext(ctx, optionalConcurrency...)
}

// GeneratePreParams finds two safe primes and computes the Paillier secret required for the protocol.
// This can be a time consuming process so it is recommended to do it out-of-band.
// If not specified, a concurrency value equal to the number of available CPU cores will be used.
// If pre-parameters could not be generated before the context is done, an error is returned.
func GeneratePreParamsWithContext(ctx context.Context, optionalConcurrency ...int) (*PaillierParams, error) {
	var concurrency int
	if 0 < len(optionalConcurrency) {
		if 1 < len(optionalConcurrency) {
			panic(errors.New("GeneratePreParams: expected 0 or 1 item in `optionalConcurrency`"))
		}
		concurrency = optionalConcurrency[0]
	} else {
		concurrency = runtime.NumCPU()
	}
	if concurrency /= 3; concurrency < 1 {
		concurrency = 1
	}

	// prepare for concurrent Paillier and safe prime generation
	paiCh := make(chan *paillier.PrivateKey, 1)
	sgpCh := make(chan []*prime.GermainSafePrime, 1)

	// 4. generate Paillier public key E_i, private key and proof
	go func(ch chan<- *paillier.PrivateKey) {
		fmt.Println("generating the Paillier modulus, please wait...")
		start := time.Now()
		// more concurrency weight is assigned here because the paillier primes have a requirement of having "large" P-Q
		PiPaillierSk, _, err := paillier.GenerateKeyPair(ctx, paillierModulusLen, concurrency*2)
		if err != nil {
			ch <- nil
			return
		}
		fmt.Printf("paillier modulus generated. took %s\n", time.Since(start))
		ch <- PiPaillierSk
	}(paiCh)

	// 5-7. generate safe primes for ZKPs used later on
	/*go func(ch chan<- []*prime.GermainSafePrime) {
		var err error
		fmt.Println("generating the safe primes for the signing proofs, please wait...")
		start := time.Now()
		sgps, err := prime.GetRandomSafePrimesConcurrent(ctx, safePrimeBitLen, 2, concurrency)
		if err != nil {
			ch <- nil
			return
		}
		fmt.Printf("safe primes generated. took %s\n", time.Since(start))
		ch <- sgps
	}(sgpCh)*/

	var err error
	fmt.Println("generating the safe primes for the signing proofs, please wait...")
	start := time.Now()
	sgps, err := prime.GetRandomSafePrimesConcurrent(ctx, safePrimeBitLen, 2, concurrency)
	if err != nil {
		return nil, errors.New("")
	}
	fmt.Printf("safe primes generated. took %s\n", time.Since(start))

	// this ticker will print a log statement while the generating is still in progress
	logProgressTicker := time.NewTicker(logProgressTickInterval)

	// errors can be thrown in the following code; consume chans to end goroutines here
	//var sgps []*prime.GermainSafePrime
	var paiSK *paillier.PrivateKey
consumer:
	for {
		select {
		case <-logProgressTicker.C:
			fmt.Println("still generating primes...")
		case sgps = <-sgpCh:
			if sgps == nil ||
				sgps[0] == nil || sgps[1] == nil ||
				!sgps[0].Prime().ProbablyPrime(30) || !sgps[1].Prime().ProbablyPrime(30) ||
				!sgps[0].SafePrime().ProbablyPrime(30) || !sgps[1].SafePrime().ProbablyPrime(30) {
				return nil, errors.New("timeout or error while generating the safe primes")
			}
			if paiSK != nil {
				break consumer
			}
		case paiSK = <-paiCh:
			if paiSK == nil {
				return nil, errors.New("timeout or error while generating the Paillier secret key")
			}
			if sgps != nil {
				break consumer
			}
		}
	}
	logProgressTicker.Stop()

	P, Q := sgps[0].SafePrime(), sgps[1].SafePrime()
	NTildei := new(big.Int).Mul(P, Q)
	modNTildeI := prime.ModInt(NTildei)

	p, q := sgps[0].Prime(), sgps[1].Prime()
	modPQ := prime.ModInt(new(big.Int).Mul(p, q))
	f1 := curve.GetRandomPositiveRelativelyPrimeInt(NTildei)
	alpha := curve.GetRandomPositiveRelativelyPrimeInt(NTildei)
	beta := modPQ.ModInverse(alpha)
	h1i := modNTildeI.Mul(f1, f1)
	h2i := modNTildeI.Exp(h1i, alpha)

	preParams := &PaillierParams{
		PaillierSK: paiSK,
		NTildei:    NTildei,
		H1i:        h1i,
		H2i:        h2i,
		Alpha:      alpha,
		Beta:       beta,
		P:          p,
		Q:          q,
	}
	return preParams, nil
}
