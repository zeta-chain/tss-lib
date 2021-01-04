// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/eddsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round5) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true

	round.allOldOK()
	round.allNewOK()

	// now we handle the private view key, if we have the view key, we check whether we receive the same as others send
	// to us. otherwise, we choose the sk have the highest frequency.
	if round.input.ViewKey.Sk == nil {
		skFreq := make(map[string]int)
		for _, val := range round.temp.skViewKey {
			counter, ok := skFreq[val.String()]
			if ok {
				skFreq[val.String()] = counter + 1
			}
			skFreq[val.String()] = 1
		}
		max := 0
		sk := big.NewInt(0)
		var ret bool
		for storedSk, freq := range skFreq {
			if freq > max {
				sk, ret = new(big.Int).SetString(storedSk, 10)
				if !ret {
					panic("it should never fail")
				}
			}
		}
		pubViewKeyX, pubViewKeyY := tss.EC().ScalarBaseMult(sk.Bytes())
		pubViewKey := crypto.NewECPointNoCurveCheck(tss.EC(), pubViewKeyX, pubViewKeyY)
		round.save.ViewKey = keygen.ViewKey{
			Sk: sk,
			Pk: pubViewKey,
		}
	} else {
		var culprits []*tss.PartyID
		for partyIndex, val := range round.temp.skViewKey {
			if val.Cmp(round.input.ViewKey.Sk) != 0 {
				culprits = append(culprits, round.OldParties().IDs()[partyIndex])
			}
		}
		if len(culprits) != 0 {
			return round.WrapError(errors.New("these culprits send me the inconsistent view address"), culprits...)
		}
		round.save.ViewKey = round.input.ViewKey
	}

	if round.IsNewCommittee() {
		// for this P: SAVE data
		round.save.BigXj = round.temp.newBigXjs
		round.save.ShareID = round.PartyID().KeyInt()
		round.save.Xi = round.temp.newXi
		round.save.Ks = round.temp.newKs

	} else if round.IsOldCommittee() {
		round.input.Xi.SetInt64(0)
	}

	round.end <- *round.save
	return nil
}

func (round *round5) CanAccept(msg tss.ParsedMessage) bool {
	return false
}

func (round *round5) Update() (bool, *tss.Error) {
	return false, nil
}

func (round *round5) NextRound() tss.Round {
	return nil // both committees are finished!
}
