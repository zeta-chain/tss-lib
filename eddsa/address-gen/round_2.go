// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package address_gen

import (
	"errors"

	"github.com/binance-chain/tss-lib/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	// 4. store r1 message pieces
	for j, msg := range round.temp.adrRound1Messages {
		r1msg := msg.Content().(*AdrRound1Message)
		round.temp.AdrCs[j] = r1msg.UnmarshalCommitment()
	}

	// now we broadcast the local r we have to all

	// 5. BROADCAST de-commitments of local r
	r2msg2 := NewKGRound2Message(round.PartyID(), round.temp.deCommitR)
	round.temp.adrRound2Messages[i] = r2msg2
	round.out <- r2msg2

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*AdrRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	// guard - VERIFY de-commit for all Pj
	for j, msg := range round.temp.adrRound2Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		msg2 := round.temp.adrRound2Messages[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
