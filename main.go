package main

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
	s256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
)

type (
	PartyData struct {
		partyId            string
		localPartySaveData *keygen.LocalPartySaveData
	}
)

func main() {
	tss.SetCurve(s256k1.S256())

	// party0 := tss.NewPartyID("id0", "moniker0", big.NewInt(1))
	// party1 := tss.NewPartyID("id0", "moniker0", big.NewInt(2))
	// party2 := tss.NewPartyID("id0", "moniker0", big.NewInt(3))

	// Create a `*PartyID` for each participating peer on the network (you should call `tss.NewPartyID` for each one)
	// parties := tss.SortPartyIDs(["id0", "id1", "id2"])
	partyIds := tss.GenerateTestPartyIDs(3)

	// Set up the parameters
	// Note: The `id` and `moniker` fields are for convenience to allow you to easily track participants.
	// The `id` should be a unique string representing this party in the network and `moniker` can be anything (even left blank).
	// The `uniqueKey` is a unique identifying key for this peer (such as its p2p public key) as a big.Int.

	ctx := tss.NewPeerContext(partyIds)

	outCh := make(chan tss.Message, 20)
	endChAggr := make(chan PartyData)

	parties := make([]tss.Party, 3)
	for i := 0; i < 3; i++ {
		params := tss.NewParameters(s256k1.S256(), ctx, partyIds[i], len(partyIds), 2)
		// When using the keygen party it is recommended that you pre-compute the "safe primes" and Paillier secret beforehand because this can take some time.
		// This code will generate those parameters using a concurrency limit equal to the number of available CPU cores.
		preParams, err := keygen.GeneratePreParams(1 * time.Minute)
		if err != nil {
			fmt.Printf("failed to generate pre params")
			return
		}
		endCh := make(chan keygen.LocalPartySaveData)
		go func(id string, chn chan keygen.LocalPartySaveData) {
			for data := range endCh {
				endChAggr <- PartyData{partyId: id, localPartySaveData: &data}
			}
		}(partyIds[i].Id, endCh)
		parties[i] = keygen.NewLocalParty(params, outCh, endCh, *preParams)
	}

	// You should keep a local mapping of `id` strings to `*PartyID` instances so that an incoming message can have its origin party's `*PartyID` recovered for passing to `UpdateFromBytes` (see below)
	partyIDMap := make(map[string]*tss.PartyID)
	partyMap := make(map[string]tss.Party)
	for i, id := range partyIds {
		partyIDMap[id.Id] = id
		partyMap[id.Id] = parties[i]
	}

	for i := 0; i < 3; i++ {
		go func(i int) {
			party := parties[i]
			fmt.Printf("Starting %s\n", party.PartyID())
			if err := party.Start(); err != nil {
				println(err)
			}
		}(i)
	}

	nkeyGenerated := 0

	for {
		select {
		case data := <-endChAggr:
			// signer := &ThresholdSigner{
			// 	groupInfo:    s.groupInfo,
			// 	thresholdKey: ThresholdKey(keygenData),
			// }
			// fmt.Println("get keygenData ", keygenData)

			curve := tss.EC()
			keygenData := data.localPartySaveData
			pkX, pkY := keygenData.ECDSAPub.X(), keygenData.ECDSAPub.Y()
			publicKey := ecdsa.PublicKey{
				Curve: curve,
				X:     pkX,
				Y:     pkY,
			}
			// fmt.Println("get publicKey ", publicKey)
			ethPublicKey := crypto.PubkeyToAddress(publicKey)
			fmt.Printf("Party %s, eth Public key %s \n", data.partyId, ethPublicKey)
			nkeyGenerated++
			if nkeyGenerated == 3 {
				return
			}
			// return //signer, nil
		case outMsg := <-outCh:
			fmt.Println("get message", outMsg)

			bytes, routing, _ := outMsg.WireBytes()

			senderPartyID := partyIDMap[routing.From.GetId()]

			if routing.IsBroadcast {
				for i := 0; i < 3; i++ {
					if parties[i].PartyID() == senderPartyID {
						continue
					}
					go func(party tss.Party, bytes []byte, senderPartyID *tss.PartyID) {
						// fmt.Printf("updating %s\n", party.PartyID().GetId())
						ok, err := party.UpdateFromBytes(
							bytes,
							senderPartyID,
							true,
						)
						if !ok || err != nil {
							fmt.Println("error", err)
						}
					}(parties[i], bytes, senderPartyID)
				}
			} else {
				for _, id := range routing.To {
					go func(party tss.Party, bytes []byte, senderPartyID *tss.PartyID) {
						// fmt.Printf("updating %s\n", party.PartyID().GetId())
						ok, err := party.UpdateFromBytes(
							bytes,
							senderPartyID,
							false,
						)
						if !ok || err != nil {
							fmt.Println("error", err)
						}
					}(partyMap[id.GetId()], bytes, senderPartyID)

				}

			}

		}
	}
}
