// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package txkeygen

import (
	"math/big"

	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/eddsa/keygen"
)

type (
	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		ShareID *big.Int
		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		// the EdDSA public key
		EDDSAPub *crypto.ECPoint // y
		// addresses passed from the sender, for testing purpose we store it here
		StealthAddress string
		// generated one-time address
		ReceiptAddress string
		ViewKey        keygen.ViewKey
	}
)

func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	return
}
