// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package address_gen

import (
	"math/big"

	"github.com/binance-chain/tss-lib/crypto"
)

type (
	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		ShareID *big.Int
		// original indexes (ki in signing preparation phase)
		Ks []*big.Int
		// generated addresses
		address *crypto.ECPoint
		bigR    *crypto.ECPoint
	}
)

func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	return
}
