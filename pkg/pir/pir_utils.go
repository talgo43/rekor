package pir

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-openapi/swag/conv"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

const (
	PIRServiceHost              = "pir-service"
	PIRServicePort              = "8787"
	PIRServicePreparePath       = "/prepare"
	PIRServiceQueryPath         = "/query"
	PIRServiceTimeout           = 30 * time.Second
	PIRServiceLengthPrefixBytes = 4
	PIRServiceEntrySizeBytes    = 2048
)

type AuthenticatedEntry struct {
	Leaf                 []byte
	Proof                [][]byte
	Root                 []byte
	TreeSize             int64
	Checkpoint           []byte
	SignedEntryTimestamp []byte
	IntegratedTime       int64
	LogId                string
	LogIndex             int64
}

type PIRLogEntry struct {
	Leaf                 []byte   `json:"leaf"`
	Proof                [][]byte `json:"proof"`
	Root                 []byte   `json:"root"`
	TreeSize             int64    `json:"treeSize"`
	Checkpoint           []byte   `json:"checkpoint"`
	SignedEntryTimestamp []byte   `json:"signedEntryTimestamp"`
	IntegratedTime       int64    `json:"integratedTime"`
	LogId                string   `json:"logId"`
}

func (authEntry *AuthenticatedEntry) ToPirEntry() PIRLogEntry {
	return PIRLogEntry{
		Leaf:                 authEntry.Leaf,
		Proof:                authEntry.Proof,
		Root:                 authEntry.Root,
		TreeSize:             authEntry.TreeSize,
		Checkpoint:           authEntry.Checkpoint,
		SignedEntryTimestamp: authEntry.SignedEntryTimestamp,
		IntegratedTime:       authEntry.IntegratedTime,
		LogId:                authEntry.LogId,
	}
}

func (pirEntry *PIRLogEntry) ToEntryAnon(logIndex int64) *models.LogEntryAnon {

	encodedHashes := []string{}
	for _, hash := range pirEntry.Proof {
		encodedHashes = append(encodedHashes, hex.EncodeToString(hash))
	}

	entry := models.LogEntryAnon{
		LogID:          &pirEntry.LogId,
		LogIndex:       &logIndex,
		Body:           base64.StdEncoding.EncodeToString(pirEntry.Leaf),
		IntegratedTime: &pirEntry.IntegratedTime,
		Verification: &models.LogEntryAnonVerification{
			InclusionProof: &models.InclusionProof{
				RootHash:   conv.Pointer(hex.EncodeToString(pirEntry.Root)),
				TreeSize:   conv.Pointer(pirEntry.TreeSize),
				LogIndex:   &logIndex,
				Hashes:     encodedHashes,
				Checkpoint: conv.Pointer(string(pirEntry.Checkpoint)),
			},
			SignedEntryTimestamp: pirEntry.SignedEntryTimestamp,
		},
	}

	return &entry
}

func AuthEntryFromEntryAnon(entry *models.LogEntryAnon) (*AuthenticatedEntry, error) {
	leaf, err := base64.StdEncoding.DecodeString(entry.Body.(string))
	if err != nil {
		return nil, err
	}

	proof := [][]byte{}
	for _, hash := range entry.Verification.InclusionProof.Hashes {
		hashBytes, err := hex.DecodeString(hash)
		if err != nil {
			return nil, err
		}

		proof = append(proof, hashBytes)
	}

	root, err := hex.DecodeString(*entry.Verification.InclusionProof.RootHash)
	if err != nil {
		return nil, err
	}

	authEntry := AuthenticatedEntry{
		Leaf:                 leaf,
		Proof:                proof,
		Root:                 root,
		TreeSize:             *entry.Verification.InclusionProof.TreeSize,
		Checkpoint:           []byte(*entry.Verification.InclusionProof.Checkpoint),
		SignedEntryTimestamp: []byte(entry.Verification.SignedEntryTimestamp),
		IntegratedTime:       *entry.IntegratedTime,
		LogId:                *entry.LogID,
		LogIndex:             *entry.LogIndex,
	}

	return &authEntry, nil
}

func VerifyAuthenticatedEntry(authEntry *AuthenticatedEntry) error {

	leafHash := rfc6962.DefaultHasher.HashLeaf(authEntry.Leaf)
	err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(authEntry.LogIndex), uint64(authEntry.TreeSize), leafHash, authEntry.Proof, authEntry.Root)
	if err != nil {
		return err
	}

	return nil
}

func GetFlattenLog(ctx context.Context, authEntries []*AuthenticatedEntry) ([][]byte, error) {
	flatDB := [][]byte{}
	for _, authEntry := range authEntries {
		rawEntry, err := json.Marshal(authEntry.ToPirEntry())
		if err != nil {
			return nil, err
		}

		paddedEntry, err := PadEntry(rawEntry)
		if err != nil {
			return nil, err
		}

		flatDB = append(flatDB, paddedEntry)
	}

	return flatDB, nil
}

func PadEntry(entry []byte) ([]byte, error) {
	if len(entry)+PIRServiceLengthPrefixBytes > PIRServiceEntrySizeBytes {
		return nil, fmt.Errorf("Record of %d bytes (+%d-byte length prefix) exceeds max entry size (%d)", len(entry), PIRServiceLengthPrefixBytes, PIRServiceEntrySizeBytes)
	}

	lengthPrefix := make([]byte, PIRServiceLengthPrefixBytes)
	binary.BigEndian.PutUint32(lengthPrefix, uint32(len(entry)))
	body := append(lengthPrefix, entry...)
	padding := make([]byte, PIRServiceEntrySizeBytes-len(body))
	return append(body, padding...), nil
}
