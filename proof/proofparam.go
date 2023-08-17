package proof

import (
	"errors"
	"github.com/zhp12543/zk-proof/dln"
	"github.com/zhp12543/zk-proof/paillier"
	"math/big"
	"sync"
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

func (pk *PaillierParams) VerifyDln( dln1 [][]byte, dln2 [][]byte) error {
	if pk.H1i.Cmp(pk.H2i) == 0 || pk.NTildei.BitLen() != paillierModulusLen ||
		pk.PaillierSK.N.BitLen() != paillierModulusLen {
		return errors.New("got paillier modulus with insufficient bits for this party")
	}

	errChain := make(chan error, 0)
	doneChain := make(chan struct{}, 0)

	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()
		dlnProof1, err := dln.UnmarshalDLNProof(dln1)
		if err != nil {
			errChain <- err
			return
		}

		if !dlnProof1.Verify(pk.H1i, pk.H2i, pk.NTildei) {
			errChain <- errors.New("dln1 verify false")
			return
		}
	}()

	go func() {
		defer wg.Done()
		dlnProof2, err := dln.UnmarshalDLNProof(dln2)
		if err != nil {
			errChain <- err
			return
		}

		if !dlnProof2.Verify(pk.H2i, pk.H1i, pk.NTildei) {
			errChain <- errors.New("dln2 verify false")
			return
		}
	}()

	go func() {
		wg.Wait()
		close(doneChain)
	}()

	select {
	case err := <-errChain:
		return err
	case <-doneChain:
		return nil
	}
}

func (pk *PaillierParams) DlnProof() ([][]byte, [][]byte, error) {
	dln1, err := dln.NewDLNProof(
		pk.H1i,
		pk.H2i,
		pk.Alpha,
		pk.P,
		pk.Q,
		pk.NTildei).Serialize()

	if err != nil {
		return nil, nil, err
	}

	dln2, err := dln.NewDLNProof(
		pk.H2i,
		pk.H1i,
		pk.Beta,
		pk.P,
		pk.Q,
		pk.NTildei).Serialize()

	if err != nil {
		return nil, nil, err
	}
	return dln1, dln2, nil
}