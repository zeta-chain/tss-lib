// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/tss"
)

var (
	// BASE_POINT2 constants for secp256k1
	// https://github.com/KZen-networks/curv/blob/91457b09deac6eb8868eaef13e08aa1625385d77/src/elliptic/curves/secp256_k1.rs#L49
	basePoint2Secp256k1X = []byte{
		0x08, 0xd1, 0x32, 0x21, 0xe3, 0xa7, 0x32, 0x6a, 0x34, 0xdd, 0x45, 0x21, 0x4b, 0xa8, 0x01, 0x16,
		0xdd, 0x14, 0x2e, 0x4b, 0x5f, 0xf3, 0xce, 0x66, 0xa8, 0xdc, 0x7b, 0xfa, 0x03, 0x78, 0xb7, 0x95,
	}
	basePoint2Secp256k1Y = []byte{
		0x5d, 0x41, 0xac, 0x14, 0x77, 0x61, 0x4b, 0x5c, 0x08, 0x48, 0xd5, 0x0d, 0xbd, 0x56, 0x5e, 0xa2,
		0x80, 0x7b, 0xcb, 0xa1, 0xdf, 0x0d, 0xf0, 0x7a, 0x82, 0x17, 0xe9, 0xf7, 0xf7, 0xc2, 0xbe, 0x88,
	}

	// BASE_POINT2 constants for P-256
	// generated externally for this test
	basePoint2P256X = []byte{
		0xbe, 0xbd, 0x79, 0xbe, 0x48, 0xf8, 0x45, 0xb4, 0x25, 0x98, 0xb7, 0xd9, 0xa0, 0x2b, 0x3d, 0x69,
		0xa5, 0x9b, 0x3e, 0xb9, 0xc1, 0xbe, 0x3a, 0x60, 0xd9, 0xb4, 0x2c, 0x22, 0x43, 0x38, 0x38, 0xd0,
	}
	basePoint2P256Y = []byte{
		0x91, 0x55, 0x33, 0xf4, 0xfb, 0xa3, 0x7b, 0x54, 0xe3, 0xf2, 0x4b, 0x5d, 0xc8, 0xcd, 0xdd, 0xd4,
		0xdd, 0xa4, 0xfe, 0x38, 0x09, 0xf3, 0x6f, 0xce, 0xec, 0x2e, 0xe3, 0xd0, 0x07, 0x87, 0xf3, 0xbe,
	}
)

func TestECBasePoint2(t *testing.T) {
	type args struct {
		curve elliptic.Curve
	}
	tests := []struct {
		name string
		args args
		wantX,
		wantY *big.Int
		wantIsOnCurve bool
		wantErr       bool
	}{{
		name:          "Deterministically produces constant coords for secp256k1 BASE_POINT2 from KZen-networks/curv",
		args:          args{btcec.S256()},
		wantX:         new(big.Int).SetBytes(basePoint2Secp256k1X),
		wantY:         new(big.Int).SetBytes(basePoint2Secp256k1Y),
		wantIsOnCurve: true,
	}, {
		name:          "Deterministically produces constant coords for a P-256 BASE_POINT2",
		args:          args{elliptic.P256()},
		wantX:         new(big.Int).SetBytes(basePoint2P256X),
		wantY:         new(big.Int).SetBytes(basePoint2P256Y),
		wantIsOnCurve: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPt, err := ECBasePoint2(tt.args.curve)
			if (err != nil) != tt.wantErr {
				t.Errorf("ECBasePoint2() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotPt == nil {
				t.Fatalf("ECBasePoint2() gotPt == nil")
			}
			if tt.wantIsOnCurve && !gotPt.IsOnCurve() {
				t.Error("ECBasePoint2() not on curve, wantIsOnCurve = true")
			}
			if gotPt.X().Cmp(tt.wantX) != 0 {
				t.Errorf("ECBasePoint2() gotX = %X, wantX %X", gotPt.X(), tt.wantX)
			}
			if gotPt.Y().Cmp(tt.wantY) != 0 {
				t.Errorf("ECBasePoint2() gotY = %X, wantY %X", gotPt.Y(), tt.wantY)
			}

			gotPtAgain, err := ECBasePoint2(tt.args.curve)
			if !assert.NoError(t, err) {
				return
			}
			if !reflect.DeepEqual(gotPt, gotPtAgain) {
				t.Errorf("ECBasePoint2() repeat invocation did not return a deep equal result")
			}
		})
	}
}

func TestGenerateAddressAndImport(t *testing.T) {
	cv := edwards.Edwards()

	ui := common.GetRandomPositiveInt(tss.EC().Params().N)
	px, py := cv.ScalarBaseMult(ui.Bytes())
	pubSignKey := NewECPointNoCurveCheck(edwards.Edwards(), px, py)

	ui2 := common.GetRandomPositiveInt(tss.EC().Params().N)
	px, py = cv.ScalarBaseMult(ui2.Bytes())
	pubViewKey := NewECPointNoCurveCheck(edwards.Edwards(), px, py)
	address := GenAddress(pubSignKey, pubViewKey)
	fmt.Printf("%v\n", address)
	fmt.Printf("%v\n", hex.EncodeToString(ui.Bytes()))
	fmt.Printf("%v\n", hex.EncodeToString(ui2.Bytes()))
	signKey, viewKey, err := RecoverPubKeys(address)
	assert.Nil(t, err)
	s1, err := DecodeGroupElementToECPoints(*signKey)
	assert.Nil(t, err)
	s2, err := DecodeGroupElementToECPoints(*viewKey)
	assert.Nil(t, err)
	assert.True(t, reflect.DeepEqual(s1.Bytes(), pubSignKey.Bytes()))
	assert.True(t, reflect.DeepEqual(s2.Bytes(), pubViewKey.Bytes()))
}

func TestGenerateAddressAndImport2(t *testing.T) {
	// viewkey := "6c0f144699231f4d1c527a23b12bb06e2f0e7a1fb2e88023cb413725d7c87a03"
	spendkey := "4b1bd20e4033a5599a21fc885cde57293c8ded409e2602adc40811ea0191da04"
	// vsk, err := hex.DecodeString(viewkey)
	ssk, err := hex.DecodeString(spendkey)
	fmt.Printf("lenth------>%v\n", len(ssk))
	assert.Nil(t, err)
	a, _, _ := RecoverPubKeys("45aSveAyRcWKunYwzWTEzyMzkgaHEJQKAdxLegP2jMRBZGsfUTynVJQGqLqfMkR5No9JnarfxbKgSWFpp2LgaioqADZRFZR")

	var src [32]byte
	copy(src[:], ssk)
	v := EncodedBytesToBigInt(&src)
	vx, vy := edwards.Edwards().ScalarBaseMult(v.Bytes())
	// sx, sy := edwards.Edwards().ScalarBaseMult(vsk)

	aa, err := DecodeGroupElementToECPoints(*a)
	assert.Nil(t, err)
	// ab, err := DecodeGroupElementToECPoints(*b)
	// assert.Nil(t, err)

	fmt.Printf("ax==%v\n", aa.X())
	fmt.Printf("ax==%v\n", vx)
	fmt.Printf("ay==%v\n", aa.Y())
	fmt.Printf("ay==%v\n", vy)
}
