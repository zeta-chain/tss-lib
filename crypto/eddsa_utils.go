// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/agl/ed25519/edwards25519"
	"github.com/decred/dcrd/dcrec/edwards/v2"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/tss"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/patcito/monero/base58"
)

func GenAddress(Key1, key2 *ECPoint) string {
	prefix := byte(thorprefix)
	var address [69]byte
	var preAddress [65]byte
	var encodedAddress [95]byte
	preAddress[0] = prefix
	pubSignKeyBytes := EcPointToEncodedBytes(Key1.X(), Key1.Y())
	pubViewKeyBytes := EcPointToEncodedBytes(key2.X(), key2.Y())
	copy(preAddress[1:33], pubSignKeyBytes[:])
	copy(preAddress[33:65], pubViewKeyBytes[:])
	// now we generated the hash
	hashVal := ecrypto.Keccak256Hash(preAddress[:])
	copy(address[:65], preAddress[:])
	copy(address[65:69], hashVal[:])
	base58.Encode(encodedAddress[:], address[:])
	return base58.EncodeToString(address[:])
}

func RecoverPubKeys(address string) (*edwards25519.ExtendedGroupElement, *edwards25519.ExtendedGroupElement, error) {
	addressByte, err := base58.DecodeString(address)
	if err != nil {
		fmt.Printf("error!!!!")
		return nil, nil, err
	}
	if addressByte[0] != thorprefix {
		return nil, nil, errors.New("invalid prefix")
	}
	var preAddress [65]byte
	copy(preAddress[:], addressByte[:65])
	hashVal := ecrypto.Keccak256Hash(preAddress[:])
	compare := hashVal.Bytes()
	checksum := addressByte[65:]
	for j, el := range compare[:4] {
		if !(el == checksum[j]) {
			return nil, nil, errors.New("invalid address")
		}
	}
	var pubSignKeyBytes, pubViewKeyBytes [32]byte
	copy(pubSignKeyBytes[:], addressByte[1:33])
	copy(pubViewKeyBytes[:], addressByte[33:65])
	fmt.Printf("VVV--->%v\n", hex.EncodeToString(pubSignKeyBytes[:]))
	fmt.Printf("VVV2--->%v\n", hex.EncodeToString(pubViewKeyBytes[:]))
	var pubSignKeyElement edwards25519.ExtendedGroupElement
	var pubViewKeyElement edwards25519.ExtendedGroupElement
	pubSignKeyElement.FromBytes(&pubSignKeyBytes)
	pubViewKeyElement.FromBytes(&pubViewKeyBytes)

	return &pubSignKeyElement, &pubViewKeyElement, nil
}

func DecodeGroupElementToECPoints(element edwards25519.ExtendedGroupElement) (*ECPoint, error) {
	var a [32]byte
	edwards25519.FeToBytes(&a, &element.X)
	var b [32]byte
	edwards25519.FeToBytes(&b, &element.Y)

	aInt := EncodedBytesToBigInt(&a)
	bInt := EncodedBytesToBigInt(&b)
	p, err := NewECPoint(edwards.Edwards(), aInt, bInt)
	return p, err
}

func EncodedBytesToBigInt(s *[32]byte) *big.Int {
	// Use a copy so we don't screw up our original
	// memory.
	sCopy := new([32]byte)
	for i := 0; i < 32; i++ {
		sCopy[i] = s[i]
	}
	reverse(sCopy)

	bi := new(big.Int).SetBytes(sCopy[:])

	return bi
}

func BigIntToEncodedBytes(a *big.Int) *[32]byte {
	s := new([32]byte)
	if a == nil {
		return s
	}

	// Caveat: a can be longer than 32 bytes.
	s = copyBytes(a.Bytes())

	// Reverse the byte string --> little endian after
	// encoding.
	reverse(s)

	return s
}

func copyBytes(aB []byte) *[32]byte {
	if aB == nil {
		return nil
	}
	s := new([32]byte)

	// If we have a short byte string, expand
	// it so that it's long enough.
	aBLen := len(aB)
	if aBLen < 32 {
		diff := 32 - aBLen
		for i := 0; i < diff; i++ {
			aB = append([]byte{0x00}, aB...)
		}
	}

	for i := 0; i < 32; i++ {
		s[i] = aB[i]
	}

	return s
}

func EcPointToEncodedBytes(x *big.Int, y *big.Int) *[32]byte {
	s := BigIntToEncodedBytes(y)
	xB := BigIntToEncodedBytes(x)
	xFE := new(edwards25519.FieldElement)
	edwards25519.FeFromBytes(xFE, xB)
	isNegative := edwards25519.FeIsNegative(xFE) == 1

	if isNegative {
		s[31] |= (1 << 7)
	} else {
		s[31] &^= (1 << 7)
	}

	return s
}

func reverse(s *[32]byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func AddExtendedElements(p, q edwards25519.ExtendedGroupElement) edwards25519.ExtendedGroupElement {
	var r edwards25519.CompletedGroupElement
	var qCached edwards25519.CachedGroupElement
	q.ToCached(&qCached)
	edwards25519.GeAdd(&r, &p, &qCached)
	var result edwards25519.ExtendedGroupElement
	r.ToExtended(&result)
	return result
}

func EcPointToExtendedElement(x *big.Int, y *big.Int) edwards25519.ExtendedGroupElement {
	encodedXBytes := BigIntToEncodedBytes(x)
	encodedYBytes := BigIntToEncodedBytes(y)

	z := common.GetRandomPositiveInt(tss.EC().Params().N)
	encodedZBytes := BigIntToEncodedBytes(z)

	var fx, fy, fxy edwards25519.FieldElement
	edwards25519.FeFromBytes(&fx, encodedXBytes)
	edwards25519.FeFromBytes(&fy, encodedYBytes)

	var X, Y, Z, T edwards25519.FieldElement
	edwards25519.FeFromBytes(&Z, encodedZBytes)

	edwards25519.FeMul(&X, &fx, &Z)
	edwards25519.FeMul(&Y, &fy, &Z)
	edwards25519.FeMul(&fxy, &fx, &fy)
	edwards25519.FeMul(&T, &fxy, &Z)

	return edwards25519.ExtendedGroupElement{
		X: X,
		Y: Y,
		Z: Z,
		T: T,
	}
}

func GenHash(hInput [32]byte) [32]byte {
	h := sha512.New()
	h.Reset()
	_, _ = h.Write(hInput[:])
	var tempHash [64]byte
	h.Sum(tempHash[:0])
	var tempHashReduced [32]byte
	edwards25519.ScReduce(&tempHashReduced, &tempHash)
	return tempHashReduced
}
