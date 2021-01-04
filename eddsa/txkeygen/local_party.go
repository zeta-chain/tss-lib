// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package txkeygen

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
)

// Implements Party
// Implements Stringer
var (
	_ tss.Party    = (*LocalParty)(nil)
	_ fmt.Stringer = (*LocalParty)(nil)
)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		temp localTempData
		data LocalPartySaveData

		// outbound messaging
		out chan<- tss.Message
		end chan<- LocalPartySaveData
	}

	localMessageStore struct {
		adrRound1Messages,
		adrRound2Messages,
		adrRound3Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after keygen)
		ri *big.Int // local r value
		// temp data for the view key shares
		AdrCs      []cmt.HashCommitment
		pubViewKey *crypto.ECPoint
		pubSignKey *crypto.ECPoint
		deCommitR  cmt.HashDeCommitment
	}
)

// Exported, used in `tss` client
func NewLocalParty(
	params *tss.Parameters,
	address string,
	out chan<- tss.Message,
	end chan<- LocalPartySaveData,
) (tss.Party, error) {
	partyCount := params.PartyCount()
	data := NewLocalPartySaveData(partyCount)
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		temp:      localTempData{},
		data:      data,
		out:       out,
		end:       end,
	}

	signKey, viewKey, err := crypto.RecoverPubKeys(address)
	if err != nil {
		return nil, fmt.Errorf("invalid stealth address with error %v\n", err)
	}
	pubSignKey, err := crypto.DecodeGroupElementToECPoints(*signKey)
	if err != nil {
		return nil, fmt.Errorf("invalid stealth address with error %v", err)
	}
	pubViewKey, err := crypto.DecodeGroupElementToECPoints(*viewKey)
	if err != nil {
		return nil, fmt.Errorf("invalid stealth address with error %v\n", err)
	}

	p.temp.pubSignKey = pubSignKey
	p.temp.pubViewKey = pubViewKey
	// msgs init
	p.temp.adrRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.adrRound2Messages = make([]tss.ParsedMessage, partyCount)
	// temp data init
	p.temp.AdrCs = make([]cmt.HashCommitment, partyCount)
	return p, nil
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName)
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := p.params.PartyCount() - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			p.params.PartyCount(), msg.GetFrom().Index), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *AdrRound1Message:
		p.temp.adrRound1Messages[fromPIdx] = msg
	case *AdrRound2Message:
		p.temp.adrRound2Messages[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		common.Logger.Warnf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

// recovers a party's original index in the set of parties during keygen
func (save LocalPartySaveData) OriginalIndex() (int, error) {
	index := -1
	ki := save.ShareID
	for j, kj := range save.Ks {
		if kj.Cmp(ki) != 0 {
			continue
		}
		index = j
		break
	}
	if index < 0 {
		return -1, errors.New("a party index could not be recovered from Ks")
	}
	return index, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
