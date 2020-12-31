// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package address_gen

import (
	"crypto/sha512"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/test"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	testParticipants = TestParticipants
	testThreshold    = TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func TestE2EConcurrentGenReceiptKey(t *testing.T) {
	setUp("info")

	tss.SetCurve(edwards.Edwards())

	threshold := testThreshold
	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater

	startGR := runtime.NumGoroutine()

	skViewKey := common.GetRandomPositiveInt(tss.EC().Params().N)
	x, y := tss.EC().ScalarBaseMult(skViewKey.Bytes())
	pubViewKey, err := crypto.NewECPoint(tss.EC(), x, y)
	assert.Nil(t, err)

	skSignKey := common.GetRandomPositiveInt(tss.EC().Params().N)
	x, y = tss.EC().ScalarBaseMult(skSignKey.Bytes())
	pubSignKey, err := crypto.NewECPoint(tss.EC(), x, y)
	assert.Nil(t, err)
	address := crypto.GenAddress(pubSignKey, pubViewKey)

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *LocalParty
		params := tss.NewParameters(p2pCtx, pIDs[i], len(pIDs), threshold)
		if i < len(fixtures) {
			ret, err := NewLocalParty(params, address, outCh, endCh)
			P = ret.(*LocalParty)
			assert.Nil(t, err)
		} else {
			ret, err := NewLocalParty(params, address, outCh, endCh)
			P = ret.(*LocalParty)
			assert.Nil(t, err)
		}
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var savedValue []LocalPartySaveData
	locker := sync.Mutex{}
	// PHASE: keygen
	var ended int32
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			atomic.AddInt32(&ended, 1)
			locker.Lock()
			savedValue = append(savedValue, save)
			locker.Unlock()
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)
				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())
				a := savedValue[0].StealthAddress
				for j, el := range savedValue {
					if j == 0 {
						continue
					}
					if !(el.StealthAddress == a) {
						t.Fatalf("the one time receipt address is not consistent")
					}
				}

				// here we verify the one-time address matches the view key
				ret := viewKeyVerify(savedValue[0], skViewKey, pubSignKey)
				assert.True(t, ret)
				// here we verify the one-time address matches the sign key that we can sign the transactions with
				// out private signing key + private view key
				ret = signingKeyVerify(savedValue[0], skSignKey, skViewKey)
				assert.True(t, ret)
				break keygen
			}
		}
	}
}

func TestE2EConcurrentGenReceiptAddressFromSender(t *testing.T) {
	// for this test, we load the stealth address from eddsa keygen saved data and verify the saved view key
	setUp("info")

	tss.SetCurve(edwards.Edwards())

	threshold := testThreshold
	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater

	startGR := runtime.NumGoroutine()

	address := fixtures[0].StealthAddress
	viewKey := fixtures[0].ViewKey
	pubSignKey := fixtures[0].EDDSAPub
	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *LocalParty
		params := tss.NewParameters(p2pCtx, pIDs[i], len(pIDs), threshold)
		if i < len(fixtures) {
			ret, err := NewLocalParty(params, address, outCh, endCh)
			P = ret.(*LocalParty)
			assert.Nil(t, err)
		} else {
			ret, err := NewLocalParty(params, address, outCh, endCh)
			P = ret.(*LocalParty)
			assert.Nil(t, err)
		}
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var savedValue []LocalPartySaveData
	locker := sync.Mutex{}
	// PHASE: keygen
	var ended int32
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			atomic.AddInt32(&ended, 1)
			locker.Lock()
			savedValue = append(savedValue, save)
			locker.Unlock()
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)
				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())
				a := savedValue[0].StealthAddress
				for j, el := range savedValue {
					if j == 0 {
						continue
					}
					if !(el.StealthAddress == a) {
						t.Fatalf("the one time receipt address is not consistent")
					}
				}
				t.Logf("the receipt address is %v\n", savedValue[0].ReceiptAddress)
				// here we verify the one-time address matches the view key
				ret := viewKeyVerify(savedValue[0], viewKey.Sk, pubSignKey)
				assert.True(t, ret)

				break keygen
			}
		}
	}
}

func signingKeyVerify(data LocalPartySaveData, skSignKey *big.Int, skViewKey *big.Int) bool {
	pub1, pub2, err := crypto.RecoverPubKeys(data.ReceiptAddress)
	if err != nil {
		return false
	}
	receiptKey, err := crypto.DecodeGroupElementToECPoints(*pub1)
	bigR, err2 := crypto.DecodeGroupElementToECPoints(*pub2)
	if err != nil || err2 != nil {
		return false
	}
	hx, hy := tss.EC().ScalarMult(bigR.X(), bigR.Y(), skViewKey.Bytes())
	hash := sha512.New()
	hash.Reset()
	_, _ = hash.Write(hx.Bytes())
	_, _ = hash.Write(hy.Bytes())
	h := hash.Sum(nil)
	hv := new(big.Int).Mod(new(big.Int).SetBytes(h), tss.EC().Params().N)
	x := new(big.Int).Add(hv, skSignKey)
	calPubKeyX, calPubKeyY := tss.EC().ScalarBaseMult(x.Bytes())
	return calPubKeyX.Cmp(receiptKey.X()) == 0 && calPubKeyY.Cmp(receiptKey.Y()) == 0
}

func viewKeyVerify(data LocalPartySaveData, skViewKey *big.Int, pubSignKey *crypto.ECPoint) bool {
	pub1, pub2, err := crypto.RecoverPubKeys(data.ReceiptAddress)
	if err != nil {
		return false
	}
	receiptKey, err := crypto.DecodeGroupElementToECPoints(*pub1)
	bigR, err2 := crypto.DecodeGroupElementToECPoints(*pub2)
	if err != nil || err2 != nil {
		return false
	}

	hx, hy := tss.EC().ScalarMult(bigR.X(), bigR.Y(), skViewKey.Bytes())
	hash := sha512.New()
	hash.Reset()
	_, _ = hash.Write(hx.Bytes())
	_, _ = hash.Write(hy.Bytes())
	h := hash.Sum(nil)
	hv := new(big.Int).Mod(new(big.Int).SetBytes(h), tss.EC().Params().N)
	px, py := tss.EC().ScalarBaseMult(hv.Bytes())
	retX, retY := tss.EC().Add(px, py, pubSignKey.X(), pubSignKey.Y())
	return retX.Cmp(receiptKey.X()) == 0 && retY.Cmp(receiptKey.Y()) == 0
}
