// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkp_test

import (
	"testing"

	s256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	. "github.com/binance-chain/tss-lib/crypto/zkp"
)

func TestSchnorrProof(t *testing.T) {
	curve := s256k1.S256()
	q := curve.Params().N
	u := common.GetRandomPositiveInt(q)
	uG := crypto.ScalarBaseMult(curve, u)
	proof, _ := NewDLogProof(curve, u, uG)

	assert.True(t, proof.Alpha.IsOnCurve())
	assert.NotZero(t, proof.Alpha.X())
	assert.NotZero(t, proof.Alpha.Y())
	assert.NotZero(t, proof.T)
}

func TestSchnorrProofVerify(t *testing.T) {
	curve := s256k1.S256()
	q := curve.Params().N
	u := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(curve, u)

	proof, _ := NewDLogProof(curve, u, X)
	res := proof.Verify(X)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrProofVerifyBadX(t *testing.T) {
	curve := s256k1.S256()
	q := curve.Params().N
	u := common.GetRandomPositiveInt(q)
	u2 := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(curve, u)
	X2 := crypto.ScalarBaseMult(curve, u2)

	proof, _ := NewDLogProof(curve, u2, X2)
	res := proof.Verify(X)

	assert.False(t, res, "verify result must be false")
}
