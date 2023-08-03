package proof

import (
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
