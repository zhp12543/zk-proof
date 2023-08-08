package mta

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/zhp12543/zk-proof/curve"
	"github.com/zhp12543/zk-proof/paillier"
	"github.com/zhp12543/zk-proof/prime"
	"math/big"
)

func AliceInit(
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	a, NTildeB, h1B, h2B *big.Int,
) (cA *big.Int, pf *RangeProofAlice, err error) {
	defer func() {
		if err1 := recover(); err1 != nil {
			err = fmt.Errorf("%+v", err1)
		}
	}()

	cA, rA, err := pkA.EncryptAndReturnRandomness(a)
	if err != nil {
		return nil, nil, err
	}
	pf, err = ProveRangeAlice(ec, pkA, cA, NTildeB, h1B, h2B, a, rA)
	return cA, pf, err
}

func BobMid(
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *RangeProofAlice,
	b, cA, NTildeA, h1A, h2A, NTildeB, h1B, h2B *big.Int,
) (beta, cB, betaPrm *big.Int, piB *ProofBob, err error) {
	defer func() {
		if err1 := recover(); err1 != nil {
			err = fmt.Errorf("%+v", err1)
		}
	}()

	if !pf.Verify(ec, pkA, NTildeB, h1B, h2B, cA) {
		err = errors.New("RangeProofAlice.Verify() returned false")
		return
	}
	q := ec.Params().N
	betaPrm = curve.GetRandomPositiveInt(pkA.N)
	cBetaPrm, cRand, err := pkA.EncryptAndReturnRandomness(betaPrm)
	if err != nil {
		return
	}
	cB, err = pkA.HomoMult(b, cA)
	if err != nil {
		return
	}
	cB, err = pkA.HomoAdd(cB, cBetaPrm)
	if err != nil {
		return
	}
	beta = prime.ModInt(q).Sub(zero, betaPrm)
	piB, err = ProveBob(ec, pkA, NTildeA, h1A, h2A, cA, cB, b, betaPrm, cRand)
	return
}

func BobMidWC(
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *RangeProofAlice,
	b, cA, NTildeA, h1A, h2A, NTildeB, h1B, h2B *big.Int,
	B *curve.ECPoint,
) (beta, cB, betaPrm *big.Int, piB *ProofBobWC, err error) {
	defer func() {
		if err1 := recover(); err1 != nil {
			err = fmt.Errorf("%+v", err1)
		}
	}()

	if !pf.Verify(ec, pkA, NTildeB, h1B, h2B, cA) {
		err = errors.New("RangeProofAlice.Verify() returned false")
		return
	}
	q := ec.Params().N
	betaPrm = curve.GetRandomPositiveInt(pkA.N)
	cBetaPrm, cRand, err := pkA.EncryptAndReturnRandomness(betaPrm)
	if err != nil {
		return
	}
	cB, err = pkA.HomoMult(b, cA)
	if err != nil {
		return
	}
	cB, err = pkA.HomoAdd(cB, cBetaPrm)
	if err != nil {
		return
	}
	beta = prime.ModInt(q).Sub(zero, betaPrm)
	piB, err = ProveBobWC(ec, pkA, NTildeA, h1A, h2A, cA, cB, b, betaPrm, cRand, B)
	return
}

func AliceEnd(
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *ProofBob,
	h1A, h2A, cA, cB, NTildeA *big.Int,
	sk *paillier.PrivateKey,
) (ret *big.Int, err error) {
	defer func() {
		if err1 := recover(); err1 != nil {
			err = fmt.Errorf("%+v", err1)
		}
	}()

	if !pf.Verify(ec, pkA, NTildeA, h1A, h2A, cA, cB) {
		return nil, errors.New("ProofBob.Verify() returned false")
	}
	alphaPrm, err := sk.Decrypt(cB)
	if err != nil {
		return nil, err
	}
	q := ec.Params().N
	return new(big.Int).Mod(alphaPrm, q), nil
}

func AliceEndWC(
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *ProofBobWC,
	B *curve.ECPoint,
	cA, cB, NTildeA, h1A, h2A *big.Int,
	sk *paillier.PrivateKey,
) (ret *big.Int, err error) {
	defer func() {
		if err1 := recover(); err1 != nil {
			err = fmt.Errorf("%+v", err1)
		}
	}()

	if !pf.Verify(ec, pkA, NTildeA, h1A, h2A, cA, cB, B) {
		return nil, errors.New("ProofBobWC.Verify() returned false")
	}
	alphaPrm, err := sk.Decrypt(cB)
	if err != nil {
		return nil, err
	}
	q := ec.Params().N
	return new(big.Int).Mod(alphaPrm, q), nil
}
