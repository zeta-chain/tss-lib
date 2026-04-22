// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// buildMaliciousBobWC replicates the Alpha-Rays / TSSHOCK PoC: Bob supplies
// an oversized betaPrm (q^7) to ProveBobWC instead of drawing it from [0, q^5).
// The returned proof is malformed but passes the pre-fix verifier, enabling
// a Paillier wrap that leaks Alice's nonce.
func buildMaliciousBobWC(t *testing.T) (
	pfB *ProofBobWC,
	pkA *paillier.PublicKey,
	NTildeA, h1A, h2A, cA, cB *big.Int,
	B *crypto.ECPoint,
	q *big.Int,
) {
	t.Helper()
	q = tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	_, pk, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)
	pkA = pk

	a := common.GetRandomPositiveInt(q)
	b := common.GetRandomPositiveInt(q)
	gBX, gBY := tss.EC().ScalarBaseMult(b.Bytes())

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(t, err)

	NTildeA, h1A, h2A = NTildei, h1i, h2i

	cA, _, err = AliceInit(tss.EC(), pkA, a, NTildej, h1j, h2j)
	assert.NoError(t, err)

	// malicious betaPrm = q^5 * q^2 = q^7, far above the GG18 q^5 bound
	q2 := new(big.Int).Mul(q, q)
	q5 := new(big.Int).Exp(q, big.NewInt(5), nil)
	maliciousBetaPrm := new(big.Int).Mul(q5, q2)

	cBetaPrmMal, cRandMal, err := pkA.EncryptAndReturnRandomness(maliciousBetaPrm)
	assert.NoError(t, err)

	cB, err = pkA.HomoMult(b, cA)
	assert.NoError(t, err)
	cB, err = pkA.HomoAdd(cB, cBetaPrmMal)
	assert.NoError(t, err)

	B, err = crypto.NewECPoint(tss.EC(), gBX, gBY)
	assert.NoError(t, err)

	pfB, err = ProveBobWC(tss.EC(), pkA, NTildeA, h1A, h2A, cA, cB, b, maliciousBetaPrm, cRandMal, B)
	assert.NoError(t, err)

	return
}

func TestProofBobWC_RejectsOversizedT1(t *testing.T) {
	pfB, pkA, NTildeA, h1A, h2A, cA, cB, B, q := buildMaliciousBobWC(t)

	q5 := new(big.Int).Exp(q, big.NewInt(5), nil)
	assert.Greater(t, pfB.T1.BitLen(), q5.BitLen(),
		"sanity: malicious T1 must exceed q^5 bit length")

	ok := pfB.Verify(tss.EC(), pkA, NTildeA, h1A, h2A, cA, cB, B)
	assert.False(t, ok, "ProofBobWC.Verify must reject an oversized T1 (q^7)")
}

func TestProofBob_RejectsOversizedT1(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	_, pkA, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	a := common.GetRandomPositiveInt(q)
	b := common.GetRandomPositiveInt(q)

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(t, err)

	cA, _, err := AliceInit(tss.EC(), pkA, a, NTildej, h1j, h2j)
	assert.NoError(t, err)

	// malicious betaPrm = q^5 * q^2 = q^7
	q2 := new(big.Int).Mul(q, q)
	q5 := new(big.Int).Exp(q, big.NewInt(5), nil)
	maliciousBetaPrm := new(big.Int).Mul(q5, q2)

	cBetaPrmMal, cRandMal, err := pkA.EncryptAndReturnRandomness(maliciousBetaPrm)
	assert.NoError(t, err)

	cB, err := pkA.HomoMult(b, cA)
	assert.NoError(t, err)
	cB, err = pkA.HomoAdd(cB, cBetaPrmMal)
	assert.NoError(t, err)

	pfB, err := ProveBob(tss.EC(), pkA, NTildei, h1i, h2i, cA, cB, b, maliciousBetaPrm, cRandMal)
	assert.NoError(t, err)

	assert.Greater(t, pfB.T1.BitLen(), q5.BitLen(),
		"sanity: malicious T1 must exceed q^5 bit length")

	ok := pfB.Verify(tss.EC(), pkA, NTildei, h1i, h2i, cA, cB)
	assert.False(t, ok, "ProofBob.Verify must reject an oversized T1 (q^7)")
}

func buildHonestBobWC(t *testing.T) (
	pfB *ProofBobWC,
	pkA *paillier.PublicKey,
	NTildeA, h1A, h2A, cA, cB *big.Int,
	B *crypto.ECPoint,
	q *big.Int,
) {
	t.Helper()
	q = tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	_, pk, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)
	pkA = pk

	a := common.GetRandomPositiveInt(q)
	b := common.GetRandomPositiveInt(q)
	gBX, gBY := tss.EC().ScalarBaseMult(b.Bytes())

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(t, err)

	NTildeA, h1A, h2A = NTildei, h1i, h2i

	cA, pfA, err := AliceInit(tss.EC(), pkA, a, NTildej, h1j, h2j)
	assert.NoError(t, err)

	B, err = crypto.NewECPoint(tss.EC(), gBX, gBY)
	assert.NoError(t, err)

	_, cB, _, pfB, err = BobMidWC(tss.EC(), pkA, pfA, b, cA, NTildeA, h1A, h2A, NTildej, h1j, h2j, B)
	assert.NoError(t, err)

	return
}

func TestProofBobWC_RejectsBelowQ(t *testing.T) {
	pfB, pkA, NTildeA, h1A, h2A, cA, cB, B, _ := buildHonestBobWC(t)
	assert.True(t, pfB.Verify(tss.EC(), pkA, NTildeA, h1A, h2A, cA, cB, B),
		"precondition: honest proof must verify")

	small := big.NewInt(1)

	cases := []struct {
		name  string
		field **big.Int
	}{
		{"S1", &pfB.S1},
		{"S2", &pfB.S2},
		{"T1", &pfB.T1},
		{"T2", &pfB.T2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := *tc.field
			*tc.field = small
			defer func() { *tc.field = orig }()

			ok := pfB.Verify(tss.EC(), pkA, NTildeA, h1A, h2A, cA, cB, B)
			assert.False(t, ok, "ProofBobWC.Verify must reject %s below q", tc.name)
		})
	}
}

func TestRangeProofAlice_RejectsBelowQ(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	m := common.GetRandomPositiveInt(q)
	c, r, err := sk.EncryptAndReturnRandomness(m)
	assert.NoError(t, err)

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)

	pf, err := ProveRangeAlice(tss.EC(), pk, c, NTildei, h1i, h2i, m, r)
	assert.NoError(t, err)
	assert.True(t, pf.Verify(tss.EC(), pk, NTildei, h1i, h2i, c),
		"precondition: honest range proof must verify")

	small := big.NewInt(1)

	cases := []struct {
		name  string
		field **big.Int
	}{
		{"S1", &pf.S1},
		{"S2", &pf.S2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := *tc.field
			*tc.field = small
			defer func() { *tc.field = orig }()

			ok := pf.Verify(tss.EC(), pk, NTildei, h1i, h2i, c)
			assert.False(t, ok, "RangeProofAlice.Verify must reject %s below q", tc.name)
		})
	}
}

// TestShareProtocol_HonestStillWorks is a regression guard ensuring the
// bounds fix does not break the honest BobMid -> AliceEnd path.
func TestShareProtocol_HonestStillWorks(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	a := common.GetRandomPositiveInt(q)
	b := common.GetRandomPositiveInt(q)

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(t, err)

	cA, pf, err := AliceInit(tss.EC(), pk, a, NTildej, h1j, h2j)
	assert.NoError(t, err)

	_, cB, betaPrm, pfB, err := BobMid(tss.EC(), pk, pf, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j)
	assert.NoError(t, err)

	alpha, err := AliceEnd(tss.EC(), pk, pfB, h1i, h2i, cA, cB, NTildei, sk)
	assert.NoError(t, err)

	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, betaPrm)
	expected := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(expected), "alpha must equal (a*b + betaPrm) mod q")
}
