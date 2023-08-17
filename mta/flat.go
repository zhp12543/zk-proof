package mta

import (
	"crypto/elliptic"
	"fmt"
	"github.com/zhp12543/zk-proof/curve"
	"math/big"
)

func (pf *ProofBob) Flat() []*big.Int {
	return []*big.Int{
		pf.Z,
		pf.ZPrm,
		pf.T,
		pf.V,
		pf.W,
		pf.S,
		pf.S1,
		pf.S2,
		pf.T1,
		pf.T2,
	}
}

func ProofBobUnFlat(in []*big.Int) (*ProofBob, error) {
	if len(in) != ProofBobBytesParts && len(in) != ProofBobWCBytesParts {
		return nil, fmt.Errorf(
			"expected %d big.Int parts to construct ProofBob, or %d for ProofBobWC",
			ProofBobBytesParts, ProofBobWCBytesParts)
	}
	return &ProofBob{
		Z:    in[0],
		ZPrm: in[1],
		T:    in[2],
		V:    in[3],
		W:    in[4],
		S:    in[5],
		S1:   in[6],
		S2:   in[7],
		T1:   in[8],
		T2:   in[9],
	}, nil
}

func (pf *ProofBobWC) Flat() []*big.Int {
	out := make([]*big.Int, 0)
	pb := pf.ProofBob.Flat()
	out = append(pb, pf.U.X())
	out = append(out, pf.U.Y())
	return out
}

func ProofBobWCUnFlat(ec elliptic.Curve, in []*big.Int) (*ProofBobWC, error) {
	proofBob, err := ProofBobUnFlat(in)
	if err != nil {
		return nil, err
	}
	point, err := curve.NewECPoint(ec,
		in[10],
		in[11])
	if err != nil {
		return nil, err
	}
	return &ProofBobWC{
		ProofBob: proofBob,
		U:        point,
	}, nil
}

func (pf *RangeProofAlice) Flat() []*big.Int {
	return []*big.Int{
		pf.Z,
		pf.U,
		pf.W,
		pf.S,
		pf.S1,
		pf.S2,
	}
}

func RangeProofAliceUnFlat(in []*big.Int) (*RangeProofAlice, error) {
	if len(in) != RangeProofAliceBytesParts {
		return nil, fmt.Errorf("expected %d big.Int parts to construct RangeProofAlice", RangeProofAliceBytesParts)
	}
	return &RangeProofAlice{
		Z:  in[0],
		U:  in[1],
		W:  in[2],
		S:  in[3],
		S1: in[4],
		S2: in[5],
	}, nil
}

