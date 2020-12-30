// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package address_gen

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
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

func TestE2EConcurrentAndSaveFixtures(t *testing.T) {
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

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *LocalParty
		params := tss.NewParameters(p2pCtx, pIDs[i], len(pIDs), threshold)
		if i < len(fixtures) {
			P = NewLocalParty(params, pubViewKey, pubSignKey, outCh, endCh).(*LocalParty)
		} else {
			P = NewLocalParty(params, pubViewKey, pubSignKey, outCh, endCh).(*LocalParty)
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
				a := savedValue[0].address
				for j, el := range savedValue {
					if j == 0 {
						continue
					}
					addr := el.address
					ret := a.X().Cmp(addr.X()) == 0 && a.Y().Cmp(addr.Y()) == 0
					if !ret {
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

func signingKeyVerify(data LocalPartySaveData, skSignKey *big.Int, skViewKey *big.Int) bool {
	hx, hy := tss.EC().ScalarMult(data.bigR.X(), data.bigR.Y(), skViewKey.Bytes())
	hash := sha512.New()
	hash.Reset()
	_, _ = hash.Write(hx.Bytes())
	_, _ = hash.Write(hy.Bytes())
	h := hash.Sum(nil)
	hv := new(big.Int).Mod(new(big.Int).SetBytes(h), tss.EC().Params().N)
	x := new(big.Int).Add(hv, skSignKey)
	calPubKeyX, calPubKeyY := tss.EC().ScalarBaseMult(x.Bytes())
	return calPubKeyX.Cmp(data.address.X()) == 0 && calPubKeyY.Cmp(data.address.Y()) == 0
}

func viewKeyVerify(data LocalPartySaveData, skViewKey *big.Int, pubSignKey *crypto.ECPoint) bool {
	hx, hy := tss.EC().ScalarMult(data.bigR.X(), data.bigR.Y(), skViewKey.Bytes())
	hash := sha512.New()
	hash.Reset()
	_, _ = hash.Write(hx.Bytes())
	_, _ = hash.Write(hy.Bytes())
	h := hash.Sum(nil)
	hv := new(big.Int).Mod(new(big.Int).SetBytes(h), tss.EC().Params().N)
	px, py := tss.EC().ScalarBaseMult(hv.Bytes())
	retX, retY := tss.EC().Add(px, py, pubSignKey.X(), pubSignKey.Y())
	return retX.Cmp(data.address.X()) == 0 && retY.Cmp(data.address.Y()) == 0
}

func tryWriteTestFixtureFile(t *testing.T, index int, data LocalPartySaveData) {
	fixtureFileName := makeTestFixtureFilePath(index)

	// fixture file does not already exist?
	// if it does, we won't re-create it here
	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			assert.NoErrorf(t, err, "unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := json.Marshal(&data)
		if err != nil {
			t.Fatalf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			t.Fatalf("unable to write to fixture file %s", fixtureFileName)
		}
		t.Logf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		t.Logf("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
	//
}
