// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package address_gen

import (
	"crypto/sha512"
	"errors"
	"math/big"

	"github.com/hashicorp/go-multierror"

	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	Ps := round.Parties().IDs()
	PIdx := round.PartyID().Index
	// 1,10. calculate xi

	// 4-12.
	type cmtOut struct {
		unWrappedErr error
		cmt          commitments.HashCommitDecommit
	}
	chs := make([]chan cmtOut, len(Ps))
	for i := range chs {
		if i == PIdx {
			continue
		}
		chs[i] = make(chan cmtOut)
	}
	shares := make([]*big.Int, len(Ps))
	shares[PIdx] = round.temp.ri
	R := new(big.Int).Set(round.temp.ri)
	for j := range Ps {
		if j == PIdx {
			continue
		}

		go func(j int, ch chan<- cmtOut) {
			r2msg1 := round.temp.adrRound2Messages[j].Content().(*AdrRound2Message)
			adrDj := r2msg1.UnmarshalDeCommitment()
			KGCj := round.temp.AdrCs[j]
			cmtDeCmt := commitments.HashCommitDecommit{C: KGCj, D: adrDj}
			ok, received := cmtDeCmt.DeCommit()
			if !ok || received == nil || received[0] == nil {
				ch <- cmtOut{errors.New("de-commitment verify failed"), cmtDeCmt}
				return
			}
			if received[0] == nil {
				panic("should not be nil")
			}
			shares[j] = received[0]
			ch <- cmtOut{nil, cmtDeCmt}
		}(j, chs[j])
	}

	vssResults := make([]cmtOut, len(Ps))
	{
		culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
		for j, Pj := range Ps {
			if j == PIdx {
				continue
			}
			vssResults[j] = <-chs[j]
			// collect culprits to error out with
			if err := vssResults[j].unWrappedErr; err != nil {
				culprits = append(culprits, Pj)
			}
		}
		var multiErr error
		if len(culprits) > 0 {
			for _, vssResult := range vssResults {
				if vssResult.unWrappedErr == nil {
					continue
				}
				multiErr = multierror.Append(multiErr, vssResult.unWrappedErr)
			}
			return round.WrapError(multiErr, culprits...)
		}
	}
	R = big.NewInt(0)
	for _, el := range shares {
		R = R.Add(R, el)
	}

	R = new(big.Int).Mod(R, tss.EC().Params().N)
	x, y := tss.EC().ScalarBaseMult(R.Bytes())
	bigR := crypto.NewECPointNoCurveCheck(tss.EC(), x, y)

	// P=H(r*A)G+B
	hx, hy := tss.EC().ScalarMult(round.temp.pubViewKey.X(), round.temp.pubViewKey.Y(), R.Bytes())
	hash := sha512.New()
	hash.Reset()
	_, _ = hash.Write(hx.Bytes())
	_, _ = hash.Write(hy.Bytes())
	h := hash.Sum(nil)

	hv := new(big.Int).Mod(new(big.Int).SetBytes(h), tss.EC().Params().N)
	px, py := tss.EC().ScalarBaseMult(hv.Bytes())
	addrx, addry := tss.EC().Add(px, py, round.temp.pubSignKey.X(), round.temp.pubSignKey.Y())

	addr := crypto.NewECPointNoCurveCheck(tss.EC(), addrx, addry)
	round.save.address = addr
	round.save.bigR = bigR
	round.end <- *round.save
	return nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round3) NextRound() tss.Round {
	return nil // finished!
}
