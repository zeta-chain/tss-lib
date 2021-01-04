// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/agl/ed25519/edwards25519"
	"github.com/pkg/errors"

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

	// 1. init R
	var R edwards25519.ExtendedGroupElement
	riBytes := crypto.BigIntToEncodedBytes(round.temp.ri)
	edwards25519.GeScalarMultBase(&R, riBytes)

	// 2-6. compute R
	i := round.PartyID().Index
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		msg := round.temp.signRound2Messages[j]
		r2msg := msg.Content().(*SignRound2Message)
		cmtDeCmt := commitments.HashCommitDecommit{C: round.temp.cjs[j], D: r2msg.UnmarshalDeCommitment()}
		ok, coordinates := cmtDeCmt.DeCommit()
		if !ok {
			return round.WrapError(errors.New("de-commitment verify failed"))
		}
		if len(coordinates) != 2 {
			return round.WrapError(errors.New("length of de-commitment should be 2"))
		}

		Rj, err := crypto.NewECPoint(tss.EC(), coordinates[0], coordinates[1])
		Rj = Rj.EightInvEight()
		if err != nil {
			return round.WrapError(errors.Wrapf(err, "NewECPoint(Rj)"), Pj)
		}
		proof, err := r2msg.UnmarshalZKProof()
		if err != nil {
			return round.WrapError(errors.New("failed to unmarshal Rj proof"), Pj)
		}
		ok = proof.Verify(Rj)
		if !ok {
			return round.WrapError(errors.New("failed to prove Rj"), Pj)
		}

		extendedRj := crypto.EcPointToExtendedElement(Rj.X(), Rj.Y())
		R = crypto.AddExtendedElements(R, extendedRj)
	}

	pub1, RElement, err := crypto.RecoverPubKeys(round.temp.receiptAddress)
	if err != nil {
		return round.WrapError(fmt.Errorf("error in recover the receipt address %v", err), nil)
	}

	receiptKey, err := crypto.DecodeGroupElementToECPoints(*pub1)
	if err != nil {
		return round.WrapError(fmt.Errorf("error in decode the receipt key with err %v", err), nil)
	}

	// 7. compute lambda
	var encodedR [32]byte
	R.ToBytes(&encodedR)
	encodedPubKey := crypto.EcPointToEncodedBytes(receiptKey.X(), receiptKey.Y())
	// h = hash512(k || A || M)
	h := sha512.New()
	h.Reset()
	_, _ = h.Write(encodedR[:])
	_, _ = h.Write(encodedPubKey[:])
	_, _ = h.Write(round.temp.m.Bytes())

	var lambda [64]byte
	h.Sum(lambda[:0])
	var lambdaReduced [32]byte
	edwards25519.ScReduce(&lambdaReduced, &lambda)

	// compute H(a*R)

	point, err := crypto.DecodeGroupElementToECPoints(*RElement)
	if err != nil {
		return round.WrapError(fmt.Errorf("error in recover the receipt address %v", err), nil)
	}
	viewSk := round.key.ViewKey.Sk
	aR := point.ScalarMult(viewSk)
	hInput := crypto.EcPointToEncodedBytes(aR.X(), aR.Y())
	reducedHash := crypto.GenHash(*hInput)
	hv := new(big.Int).Mod(new(big.Int).SetBytes(reducedHash[:]), tss.EC().Params().N)

	var localTemp2, sendS [32]byte
	var localSecret [32]byte
	edwards25519.ScMulAdd(&sendS, &lambdaReduced, crypto.BigIntToEncodedBytes(round.temp.wi), riBytes)
	// localtemp2=h_1*(h_2(a*R))
	edwards25519.ScMulAdd(&localTemp2, &lambdaReduced, crypto.BigIntToEncodedBytes(hv), crypto.BigIntToEncodedBytes(big.NewInt(0)))
	edwards25519.ScMulAdd(&localSecret, &sendS, crypto.BigIntToEncodedBytes(big.NewInt(1)), &localTemp2)
	// 8. compute si
	// 9. store r3 message pieces
	round.temp.temp2 = &localTemp2
	round.temp.si = &localSecret
	round.temp.r = crypto.EncodedBytesToBigInt(&encodedR)

	// 10. broadcast si to other parties
	r3msg := NewSignRound3Message(round.PartyID(), crypto.EncodedBytesToBigInt(&sendS))
	round.temp.signRound3Messages[round.PartyID().Index] = r3msg
	round.out <- r3msg

	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
