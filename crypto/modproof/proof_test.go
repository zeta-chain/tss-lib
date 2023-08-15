// Copyright © 2019-2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package modproof_test

import (
	"testing"
	"time"

	. "github.com/binance-chain/tss-lib/crypto/modproof"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/stretchr/testify/assert"
)

func TestMod(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)

	P, Q, N := preParams.PaillierSK.P, preParams.PaillierSK.Q, preParams.PaillierSK.N

	proof, err := NewProof(N, P, Q)
	assert.NoError(test, err)

	proofBzs := proof.Bytes()
	proof, err = NewProofFromBytes(proofBzs[:])
	assert.NoError(test, err)

	ok := proof.Verify(N)
	assert.True(test, ok, "proof must verify")
}
