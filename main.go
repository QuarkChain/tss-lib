package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/ecdsa/signing"
	"github.com/binance-chain/tss-lib/tss"
	s256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
)

type (
	PartyData struct {
		partyId            string
		localPartySaveData *keygen.LocalPartySaveData
	}

	SigningPartyData struct {
		partyId       string
		signatureData *common.SignatureData
	}
)

const (
	threshold = 1
	nparty    = 3
)

func startKeygen() (tss.SortedPartyIDs, []*keygen.LocalPartySaveData) {
	tss.SetCurve(s256k1.S256())

	// Create a `*PartyID` for each participating peer on the network (you should call `tss.NewPartyID` for each one)
	partyIds := tss.GenerateTestPartyIDs(nparty)

	// Set up the parameters
	// Note: The `id` and `moniker` fields are for convenience to allow you to easily track participants.
	// The `id` should be a unique string representing this party in the network and `moniker` can be anything (even left blank).
	// The `uniqueKey` is a unique identifying key for this peer (such as its p2p public key) as a big.Int.

	ctx := tss.NewPeerContext(partyIds)

	outCh := make(chan tss.Message, 20)
	endChAggr := make(chan PartyData)

	parties := make([]tss.Party, nparty)
	for i := 0; i < nparty; i++ {
		params := tss.NewParameters(s256k1.S256(), ctx, partyIds[i], len(partyIds), threshold)
		// When using the keygen party it is recommended that you pre-compute the "safe primes" and Paillier secret beforehand because this can take some time.
		// This code will generate those parameters using a concurrency limit equal to the number of available CPU cores.
		fmt.Printf("Starting keygen %s\n", partyIds[i])
		preParams, err := keygen.GeneratePreParams(1 * time.Minute)
		if err != nil {
			fmt.Printf("failed to generate pre params")
			return nil, nil
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

	for i := 0; i < nparty; i++ {
		go func(i int) {
			party := parties[i]
			if err := party.Start(); err != nil {
				println(err)
			}
		}(i)
	}

	nkeyGenerated := 0
	allSavedData := make([]*keygen.LocalPartySaveData, 3)

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
			for i := 0; i < nparty; i++ {
				if parties[i].PartyID().Id == data.partyId {
					allSavedData[i] = data.localPartySaveData
					break
				}
			}

			if nkeyGenerated == nparty {
				return partyIds, allSavedData
			}
			// return //signer, nil
		case outMsg := <-outCh:
			fmt.Println("get keygen message", outMsg)

			bytes, routing, _ := outMsg.WireBytes()

			senderPartyID := partyIDMap[routing.From.GetId()]

			if routing.IsBroadcast {
				for i := 0; i < nparty; i++ {
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

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
// This is borrowed from crypto/ecdsa.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func startSigning(allPartyIds tss.SortedPartyIDs, enable []bool, allLocalDataList []*keygen.LocalPartySaveData) {
	active := 0

	var partyIds tss.SortedPartyIDs
	var localDataList []*keygen.LocalPartySaveData

	for i := 0; i < len(allPartyIds); i++ {
		if !enable[i] {
			continue
		}

		allPartyIds[i].Index = active

		active++

		partyIds = append(partyIds, allPartyIds[i])
		localDataList = append(localDataList, allLocalDataList[i])
	}

	ctx := tss.NewPeerContext(partyIds)

	outCh := make(chan tss.Message, 20)
	endChAggr := make(chan SigningPartyData)

	parties := make([]tss.Party, len(partyIds))

	hash := make([]byte, 32)
	for i := 0; i < len(hash); i++ {
		hash[i] = byte(i)
	}

	for i := 0; i < len(partyIds); i++ {
		params := tss.NewParameters(s256k1.S256(), ctx, partyIds[i], len(partyIds), threshold)
		endCh := make(chan common.SignatureData)
		go func(id string, chn chan common.SignatureData) {
			for data := range endCh {
				endChAggr <- SigningPartyData{partyId: id, signatureData: &data}
			}
		}(partyIds[i].Id, endCh)
		parties[i] = signing.NewLocalParty(hashToInt(hash, s256k1.S256()), params, *localDataList[i], outCh, endCh)
	}

	partyIDMap := make(map[string]*tss.PartyID)
	partyMap := make(map[string]tss.Party)
	for i, id := range partyIds {
		partyIDMap[id.Id] = id
		partyMap[id.Id] = parties[i]
	}

	for i := 0; i < len(partyIds); i++ {
		go func(i int) {
			party := parties[i]
			fmt.Printf("Starting signing %s\n", party.PartyID())
			if err := party.Start(); err != nil {
				println(err)
			}
		}(i)
	}

	nkeySigned := 0

	for {
		select {
		case data := <-endChAggr:
			signData := data.signatureData

			fmt.Printf("Party %s, eth signature key %s \n", data.partyId, hex.EncodeToString(signData.Signature))
			sig := make([]byte, 65)
			copy(sig, signData.R)
			copy(sig[32:], signData.S)
			sig[64] = signData.SignatureRecovery[0]
			rpk, err := crypto.SigToPub(hash, sig)

			if err != nil {
				fmt.Printf("%s\n", err)
				return
			}

			recoveredAddr := crypto.PubkeyToAddress(*rpk)
			fmt.Printf("Party %s, recovery addr %s\n", data.partyId, hex.EncodeToString(recoveredAddr[:]))

			nkeySigned++

			if nkeySigned == active {
				return
			}
			// return //signer, nil
		case outMsg := <-outCh:
			fmt.Println("get signing message", outMsg)

			bytes, routing, _ := outMsg.WireBytes()

			senderPartyID := partyIDMap[routing.From.GetId()]

			if routing.IsBroadcast {
				for i := 0; i < len(partyIds); i++ {
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
					party := partyMap[id.GetId()]
					if party == nil {
						fmt.Printf("skipping updating %s\n", id)
						continue
					}

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
					}(party, bytes, senderPartyID)

				}

			}
		}
	}
}

func main() {
	partyIds, localData := startKeygen()

	startSigning(partyIds, []bool{true, true, false}, localData)

	startSigning(partyIds, []bool{false, true, true}, localData)

	startSigning(partyIds, []bool{true, false, true}, localData)
}
