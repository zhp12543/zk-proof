package proof

import (
	"errors"
	"github.com/zhp12543/zk-proof/paillier"
	"math/big"
)

type PaillierParams struct {
	PaillierSK *paillier.PrivateKey // ski
	NTildei,
	H1i, H2i,
	Alpha, Beta,
	P, Q *big.Int
}

func (p *PaillierParams) FlatPaillierPublic() []*big.Int {
	flat := make([]*big.Int, 0)
	flat = append(flat, p.PaillierSK.PublicKey.N)
	flat = append(flat, p.NTildei)
	flat = append(flat, p.H1i)
	flat = append(flat, p.H2i)
	return flat
}

func UnFlatPaillierPublic(in []*big.Int) (*PaillierParams, error) {
	if len(in) != 4 {
		return nil, errors.New("params in len error")
	}

	p := new(PaillierParams)
	p.PaillierSK = new(paillier.PrivateKey)
	p.PaillierSK.PublicKey = paillier.PublicKey{N: in[0]}
	p.NTildei = in[1]
	p.H1i = in[2]
	p.H2i = in[3]
	return p, nil
}
