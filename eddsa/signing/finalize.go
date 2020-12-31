// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/agl/ed25519/edwards25519"
	"github.com/decred/dcrd/dcrec/edwards/v2"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	sumS := round.temp.si
	for j := range round.Parties().IDs() {
		round.ok[j] = true
		if j == round.PartyID().Index {
			continue
		}
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		sjBytes := crypto.BigIntToEncodedBytes(r3msg.UnmarshalS())
		var tmpSumS [32]byte
		edwards25519.ScMulAdd(&tmpSumS, sumS, crypto.BigIntToEncodedBytes(big.NewInt(1)), sjBytes)
		sumS = &tmpSumS
	}
	s := crypto.EncodedBytesToBigInt(sumS)

	// save the signature for final output
	signature := new(common.ECSignature)
	signature.Signature = append(crypto.BigIntToEncodedBytes(round.temp.r)[:], sumS[:]...)
	signature.R = round.temp.r.Bytes()
	signature.S = s.Bytes()
	signature.M = round.temp.m.Bytes()
	round.data.Signature = signature

	pub1, _, err := crypto.RecoverPubKeys(round.temp.receiptAddress)
	if err != nil {
		return round.WrapError(fmt.Errorf("fail to recover the receipt address with error %v\n", err), nil)
	}
	receiptKey, err := crypto.DecodeGroupElementToECPoints(*pub1)

	pk := edwards.PublicKey{
		Curve: tss.EC(),
		X:     receiptKey.X(),
		Y:     receiptKey.Y(),
	}

	ok := edwards.Verify(&pk, round.temp.m.Bytes(), round.temp.r, s)
	if !ok {
		return round.WrapError(fmt.Errorf("signature verification failed"))
	}
	round.end <- round.data

	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
