// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package address_gen

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	cmts "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
)

var zero = big.NewInt(0)

// round 1 represents round 1 of the keygen part of the EDDSA TSS spec
func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
	}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	// 1. calculate "partial" share R
	ri := common.GetRandomPositiveInt(tss.EC().Params().N)
	round.temp.ri = ri

	// 2. make commitment -> (C, D)
	cmt := cmts.NewHashCommitment(ri)

	round.temp.deCommitR = cmt.D

	// BROADCAST commitments
	{
		msg := NewKGRound1Message(round.PartyID(), cmt.C)
		round.temp.adrRound1Messages[i] = msg
		round.out <- msg
	}
	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*AdrRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.adrRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		// vss check is in round 2
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
