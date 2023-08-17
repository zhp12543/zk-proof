package facproof

import (
	"errors"
	"math/big"
)

func (pf *ProofFac) Flat() []*big.Int {
	return []*big.Int{
		pf.P,
		pf.Q,
		pf.A,
		pf.B,
		pf.T,
		pf.Sigma,
		pf.Z1,
		pf.Z2,
		pf.W1,
		pf.W2,
		pf.V,
	}
}

func ProofFacUnFlat(in []*big.Int) (*ProofFac, error) {
	if len(in) != ProofFacBytesParts {
		return nil, errors.New("ProofFacUnFlat len error")
	}

	return &ProofFac{
		P: in[0], Q: in[1], A: in[2], B: in[3], T: in[4],
		Sigma: in[5], Z1: in[6], Z2: in[7], W1: in[8], W2: in[9], V: in[10],
	}, nil
}
