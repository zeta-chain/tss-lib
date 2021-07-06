// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkp

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
)

type (
	// Schnorr ZK of the discrete logarithm of pho_i such that A = g^pho (GG18)
	DLogProof struct {
		Alpha *crypto.ECPoint
		T     *big.Int
		Curve elliptic.Curve
	}
)

// NewDLogProof constructs a new Schnorr ZK of the discrete logarithm of pho_i such that A = g^pho (GG18)
func NewDLogProof(curve elliptic.Curve, x *big.Int, X *crypto.ECPoint) (*DLogProof, error) {
	if x == nil || X == nil || !X.ValidateBasic() {
		return nil, errors.New("NewDLogProof received nil or invalid value(s)")
	}
	ecParams := curve.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(curve, ecParams.Gx, ecParams.Gy) // already on the curve.

	a := common.GetRandomPositiveInt(q)
	alpha := crypto.ScalarBaseMult(curve, a)

	var c *big.Int
	{
		cHash := common.SHA512_256i(X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	t := new(big.Int).Mul(c, x)
	t = common.ModInt(q).Add(a, t)

	return &DLogProof{Alpha: alpha, T: t, Curve: curve}, nil
}

// NewDLogProof verifies a new Schnorr ZK proof of knowledge of the discrete logarithm (GG18Spec Fig. 16)
func (pf *DLogProof) Verify(X *crypto.ECPoint) bool {
	if pf == nil || !pf.ValidateBasic() {
		return false
	}
	ecParams := pf.Curve.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(pf.Curve, ecParams.Gx, ecParams.Gy)

	var c *big.Int
	{
		cHash := common.SHA512_256i(X.X(), X.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	tG := crypto.ScalarBaseMult(pf.Curve, pf.T)
	Xc := X.ScalarMult(c)
	aXc, err := pf.Alpha.Add(Xc)
	if err != nil {
		return false
	}
	if aXc.X().Cmp(tG.X()) != 0 || aXc.Y().Cmp(tG.Y()) != 0 {
		return false
	}
	return true
}

func (pf *DLogProof) ValidateBasic() bool {
	return pf.T != nil && pf.Alpha != nil && pf.Alpha.ValidateBasic()
}
