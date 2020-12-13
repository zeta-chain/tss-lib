# Multi-Party Threshold Signature Scheme
[![MIT licensed][1]][2] [![GoDoc][3]][4] [![Go Report Card][5]][6]

[1]: https://img.shields.io/badge/license-MIT-blue.svg
[2]: LICENSE
[3]: https://godoc.org/github.com/binance-chain/tss-lib?status.svg
[4]: https://godoc.org/github.com/binance-chain/tss-lib
[5]: https://goreportcard.com/badge/github.com/binance-chain/tss-lib
[6]: https://goreportcard.com/report/github.com/binance-chain/tss-lib

Permissively MIT Licensed.

Note: This is a library for developers. You may find a TSS tool that you can use with the Binance Chain CLI [here](https://docs.binance.org/tss.html).

## Introduction
This is an implementation of multi-party {t,n}-threshold ECDSA (Elliptic Curve Digital Signature Algorithm) based on Gennaro and Goldfeder __2020__ \[1\] and EdDSA (Edwards-curve Digital Signature Algorithm) following a similar approach.

This library includes three protocols:

* Key Generation for creating secret shares with no trusted dealer ("keygen").
* Signing for using the secret shares to generate a signature ("signing"). 
* Dynamic Groups to change the group of participants while keeping the secret ("resharing").

😍 This library now supports one-round signing introduced in the new GG20 paper. See the dedicated section about that below.

⚠️ Do not miss [these important notes](#how-to-use-this-securely) on implementing this library securely

## Tss Blame scheme and Security
The Thorchain Tss blame scheme is achieved in two aspects, the fist one is called the blame in malicious communication. Thorchain Tss achieves that by
implementing ([Thorchain go-tss implementation](https://gitlab.com/thorchain/tss/go-tss)) a reliable communication scheme which avoids the malicious nodes send different
tss shares to different nodes. By asking all the tss shares to be sent with a signature, tss nodes can easily trace the source of the
incorrect tss shares. By caching the shares, the system avoids the malicious nodes reset the victim's tss status by re-send any valid tss message.

The second aspect is the identifying aborts in Tss cryptographic process which is implemented in this repository.

### Keygen identifying abort

* Since each node share their secret though verifiable secret sharing,
thus when a node receives an invalid share, it will abort the keygen process and blame the node who sends the invalid share.

* If the attacker attacks the system in the round that related with the zero knowledge proof (e.g., proving that he
knows the secret x or proving the correctness of the paillier key), the nodes will also blame that attacker.

### Keysign identifying abort

#### keysign steps in high level

1. nodes randomly select their local <img src="https://latex.codecogs.com/svg.latex?\small&space;x_i"/>,<img src="https://latex.codecogs.com/svg.latex?\small&space;\gamma_i"/> and calcualte the commitment of <img src="https://latex.codecogs.com/svg.latex?\small&space;g^\gamma_i"/>.

2. nodes involve in the **MtA** and **MtAwc** to calculate the node's local share of <img src="https://latex.codecogs.com/svg.latex?\small&space;kx"/> and <img src="https://latex.codecogs.com/svg.latex?\small&space;k\gamma"/>.

3. nodes reconstruct the <img src="https://latex.codecogs.com/svg.latex?\small&space;k\gamma"/>, and proof that he holds
the share <img src="https://latex.codecogs.com/svg.latex?\small&space;kw"/>.

4. nodes calculate the <img src="https://latex.codecogs.com/svg.latex?\small&space;R"/>.

5. by exchange the <img src="https://latex.codecogs.com/svg.latex?\small&space;R^{k_i}"/>, nodes can check the correctness of
<img src="https://latex.codecogs.com/svg.latex?\small&space;R^k_i"/>. Nodes also prove the consistency between 
the value <img src="https://latex.codecogs.com/svg.latex?\small&space;R_i"/> and <img src="https://latex.codecogs.com/svg.latex?\small&space;k_i"/>,
and check <img src="https://latex.codecogs.com/svg.latex?\small&space;g \stackrel{?}{=}\prod \overline{R}_{i}"/>. 

6. similar to step 5, nodes exchanges the  <img src="https://latex.codecogs.com/svg.latex?\small&space; S_i"/> and prove the consistency
between <img src="https://latex.codecogs.com/svg.latex?\small&space;S_i=R^{k_ix_i}"/> and <img src="https://latex.codecogs.com/svg.latex?\small&space;T_i"/> where
<img src="https://latex.codecogs.com/svg.latex?\small&space;T_i"/> is a security auxiliary, and check <img src="https://latex.codecogs.com/svg.latex?\small&space;y \stackrel{?}{=}\prod {S}_{i}"/>. 

7. nodes broadcast the <img src="https://latex.codecogs.com/svg.latex?\small&space;s_i"/> which is the share of the signature <img src="https://latex.codecogs.com/svg.latex?\small&space;s"/>
and generate the signature <img src="https://latex.codecogs.com/svg.latex?\small&space;<R,S>"/> to the message <img src="https://latex.codecogs.com/svg.latex?\small&space;m"/>.

#### identifying abort supports in this repository
* Our Tss library can identify the malicious nodes and aborts the processing when the invalid message is received
in step 2,3 as the broadcast proof sent from the malicious nodes do not match with the message it claims later.

* For the invalid signature in the step 7, if the keysign pass the steps 5,6, nodes can check if <img src="https://latex.codecogs.com/svg.latex?\small&space;R^{s_i}=\overline{R}_i^m \cdot S_i^r"/> where <img src="https://latex.codecogs.com/svg.latex?\small&space;\overline{R}_i=R^{k_i}"/>.
to figure out the culprits.

* Our Tss lib can also identify the culprits if tss fail in  <img src="https://latex.codecogs.com/svg.latex?\small&space;g \stackrel{?}{=}\prod \overline{R}_{i}"/> or
<img src="https://latex.codecogs.com/svg.latex?\small&space;y \stackrel{?}{=}\prod {S}_{i}"/>.

    For the Tss algorithm, it is safe to publish the nodes' <img src="https://latex.codecogs.com/svg.latex?\small&space;k_i"/> **if node dos not send its signature share <img src="https://latex.codecogs.com/svg.latex?\small&space;s_i"/> to the public if they fail in keysign**, thus,
nodes can exchange their ephemeral value <img src="https://latex.codecogs.com/svg.latex?\small&space;k_i,\gamma_i"/> to figure out the malicious nodes who fail the check <img src="https://latex.codecogs.com/svg.latex?\small&space;g \stackrel{?}{=}\prod \overline{R}_{i}"/>.

    To figure out who fails the check <img src="https://latex.codecogs.com/svg.latex?\small&space;y \stackrel{?}{=}\prod {S}_{i}"/>,
nodes just need to broadcast their first part of the **MtA** result. Since all the peers can only get the ephemeral value <img src="https://latex.codecogs.com/svg.latex?\small&space;k_i,\gamma_i"/>
while not the signature part <img src="https://latex.codecogs.com/svg.latex?\small&space;s_i"/>, no one can
recover the secret key share of any nodes.






 


## Rationale
ECDSA is used extensively for crypto-currencies such as Bitcoin, Ethereum (secp256k1 curve), NEO (NIST P-256 curve) and many more. 

EdDSA is used extensively for crypto-currencies such as Cardano, Aeternity, Stellar Lumens and many more.

For such currencies this technique may be used to create crypto wallets where multiple parties must collaborate to sign transactions. See [MultiSig Use Cases](https://en.bitcoin.it/wiki/Multisignature#Multisignature_Applications)

One secret share per key/address is stored locally by each participant and these are kept safe by the protocol – they are never revealed to others at any time. Moreover, there is no trusted dealer of the shares.

In contrast to MultiSig solutions, transactions produced by TSS preserve the privacy of the signers by not revealing which `t+1` participants were involved in their signing.

There is also a performance bonus in that blockchain nodes may check the validity of a signature without any extra MultiSig logic or processing.

## Usage
You should start by creating an instance of a `LocalParty` and giving it the arguments that it needs.

The `LocalParty` that you use should be from the `keygen`, `signing` or `resharing` package depending on what you want to do.

### Setup
```go
// Set up elliptic curve
// use ECDSA, which is used by default
tss.SetCurve(s256k1.S256()) 
// or use EdDSA
// tss.SetCurve(edwards.Edwards()) 

// When using the keygen party it is recommended that you pre-compute the "safe primes" and Paillier secret beforehand because this can take some time.
// This code will generate those parameters using a concurrency limit equal to the number of available CPU cores.
preParams, _ := keygen.GeneratePreParams(1 * time.Minute)

// Create a `*PartyID` for each participating peer on the network (you should call `tss.NewPartyID` for each one)
parties := tss.SortPartyIDs(getParticipantPartyIDs())

// Set up the parameters
// Note: The `id` and `moniker` fields are for convenience to allow you to easily track participants.
// The `id` should be a unique string representing this party in the network and `moniker` can be anything (even left blank).
// The `uniqueKey` is a unique identifying key for this peer (such as its p2p public key) as a big.Int.
thisParty := tss.NewPartyID(id, moniker, uniqueKey)
ctx := tss.NewPeerContext(parties)
params := tss.NewParameters(ctx, thisParty, len(parties), threshold)

// You should keep a local mapping of `id` strings to `*PartyID` instances so that an incoming message can have its origin party's `*PartyID` recovered for passing to `UpdateFromBytes` (see below)
partyIDMap := make(map[string]*PartyID)
for _, id := range parties {
    partyIDMap[id.Id] = id
}
```

### Keygen
Use the `keygen.LocalParty` for the keygen protocol. The save data you receive through the `endCh` upon completion of the protocol should be persisted to secure storage.

```go
party := keygen.NewLocalParty(params, outCh, endCh, preParams) // Omit the last arg to compute the pre-params in round 1
go func() {
    err := party.Start()
    // handle err ...
}()
```

### Signing
Use the `signing.LocalParty` for signing and provide it with a `message` to sign. It requires the key data obtained from the keygen protocol. The signature will be sent through the `endCh` once completed.

Please note that `t+1` signers are required to sign a message and no more than this should be involved in the messaging rounds. Each signer should have the same view of who the `t+1` signers are.

```go
party := signing.NewLocalParty(message, params, ourKeyData, outCh, endCh)
go func() {
    err := party.Start()
    // handle err ...
}()
```

By default the library will perform all signing rounds "online" in a similar way to GG18. If you would like to use one-round signing see the next section.

#### One-Round Signing

The new implementation for GG20 supports one-round signing.

There are some pre-processing rounds that need to be done when you know the T+1 signers, but the message doesn't have to be known until the final round.
Here's a brief summary of how to use this mode:

1. Use nil as the `msg` in the `signing.NewLocalParty` constructor function.
2. The `SignatureData` produced through the `end` channel contains `OneRoundData` but no final signature.
3. Pass this partial `SignatureData` to `signing.FinalizeGetOurSigShare` with your `msg`; this produces `s_i`.
4. Share `s_i` with other parties that know that msg however you'd like. This could even happen on-chain.
5. Pass all party IDs and `s_i` to `signing.FinalizeGetAndVerifyFinalSig`. You will get a `SignatureData` populated with a full ECDSA signature.

### Re-Sharing
Use the `resharing.LocalParty` to re-distribute the secret shares. The save data received through the `endCh` should overwrite the existing key data in storage, or write new data if the party is receiving a new share.

Please note that `ReSharingParameters` is used to give this Party more context about the re-sharing that should be carried out.

```go
party := resharing.NewLocalParty(params, ourKeyData, outCh, endCh)
go func() {
    err := party.Start()
    // handle err ...
}()
```

⚠️ During re-sharing the key data may be modified during the rounds. Do not ever overwrite any data saved on disk until the final struct has been received through the `end` channel.

## Messaging
In these examples the `outCh` will collect outgoing messages from the party and the `endCh` will receive save data or a signature when the protocol is complete.

During the protocol you should provide the party with updates received from other participating parties on the network.

A `Party` has two thread-safe methods on it for receiving updates.
```go
// The main entry point when updating a party's state from the wire
UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (ok bool, err *tss.Error)
// You may use this entry point to update a party's state when running locally or in tests
Update(msg tss.ParsedMessage) (ok bool, err *tss.Error)
```

And a `tss.Message` has the following two methods for converting messages to data for the wire:
```go
// Returns the encoded message bytes to send over the wire along with routing information
WireBytes() ([]byte, *tss.MessageRouting, error)
// Returns the protobuf wrapper message struct, used only in some exceptional scenarios (i.e. mobile apps)
WireMsg() *tss.MessageWrapper
```

In a typical use case, it is expected that a transport implementation will consume message bytes via the `out` channel of the local `Party`, send them to the destination(s) specified in the result of `msg.GetTo()`, and pass them to `UpdateFromBytes` on the receiving end.

This way there is no need to deal with Marshal/Unmarshalling Protocol Buffers to implement a transport.

## How to use this securely

⚠️ This section is important. Be sure to read it!

The transport for messaging is left to the application layer and is not provided by this library. Each one of the following paragraphs should be read and followed carefully as it is crucial that you implement a secure transport to ensure safety of the protocol.

When you build a transport, it should offer a broadcast channel as well as point-to-point channels connecting every pair of parties. Your transport should also employ suitable end-to-end encryption (TLS with an [AEAD cipher](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD)) is recommended) between parties to ensure that a party can only read the messages sent to it.

Within your transport, each message should be wrapped with a **session ID** that is unique to a single run of the keygen, signing or re-sharing rounds. This session ID should be agreed upon out-of-band and known only by the participating parties before the rounds begin. Upon receiving any message, your program should make sure that the received session ID matches the one that was agreed upon at the start.

Additionally, there should be a mechanism in your transport to allow for "reliable broadcasts", meaning parties can broadcast a message to other parties such that it's guaranteed that each one receives the same message. There are several examples of algorithms online that do this by sharing and comparing hashes of received messages.

Timeouts and errors should be handled by your application. The method `WaitingFor` may be called on a `Party` to get the set of other parties that it is still waiting for messages from. You may also get the set of culprit parties that caused an error from a `*tss.Error`.

## Security Audit
A full review of this library was carried out by Kudelski Security and their final report was made available in October, 2019. A copy of this report [`audit-binance-tss-lib-final-20191018.pdf`](https://github.com/binance-chain/tss-lib/releases/download/v1.0.0/audit-binance-tss-lib-final-20191018.pdf) may be found in the v1.0.0 release notes of this repository.

## References
\[1\] https://eprint.iacr.org/2020/540.pdf
