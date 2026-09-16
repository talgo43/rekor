package pirsnapshot

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/google/trillian"
	internalclient "github.com/sigstore/rekor/internal/trillianclient"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc/codes"
)

func ExportLogEntries(ctx context.Context, tc internalclient.Client, N int64) ([]*trillian.GetEntryAndProofResponse, error) {
	leavesWithProofs := []*trillian.GetEntryAndProofResponse{}
	i := int64(0)
	for i = range N {
		resp := tc.GetLeafAndProofByIndex(ctx, i)
		if resp.Status != codes.OK {
			log.ContextLogger(ctx).Errorf("Error getting leaf with proof at index %d, code: %s", i, resp.Status.String())
			return nil, fmt.Errorf("Error getting leaf with proof at index %d, code: %s", i, resp.Status.String())

		}

		result := resp.GetLeafAndProofResult
		leaf := result.Leaf
		if leaf == nil {
			log.ContextLogger(ctx).Errorf("leaf is null at index %d", i)
			return nil, fmt.Errorf("leaf is null at index %d", i)
		}

		leavesWithProofs = append(leavesWithProofs, result)
	}

	return leavesWithProofs, nil
}

func VerifyExportedLogEntries(ctx context.Context, logEntries []*trillian.GetEntryAndProofResponse) error {
	for i, entry := range logEntries {
		root, err := internalclient.UnmarshalLogRoot(entry.GetSignedLogRoot().GetLogRoot())
		if err != nil {
			log.ContextLogger(ctx).Errorf("Failed unmarshal log root for entry %d", i)
			return err
		}

		leafHash := rfc6962.DefaultHasher.HashLeaf(entry.GetLeaf().GetLeafValue())
		err = proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(i), root.TreeSize, leafHash, entry.GetProof().GetHashes(), root.RootHash)
		if err != nil {
			return err
		}
	}

	log.ContextLogger(ctx).Debugf("Exported Log was verified successfully")
	return nil
}

type pirEntry struct {
	Leaf  []byte   `json:"leaf"`
	Proof [][]byte `json:"proof"`
	Root  []byte   `json:"root"`
}

const (
	LengthPrefixBytes = 4
	EntrySizeBytes    = 1024
)

func FlattenForPIR(ctx context.Context, logEntries []*trillian.GetEntryAndProofResponse) ([][]byte, error) {
	flat_db := [][]byte{}
	for _, entry := range logEntries {
		pirEntry := pirEntry{
			Leaf:  entry.GetLeaf().GetLeafValue(),
			Proof: entry.GetProof().GetHashes(),
			Root:  entry.GetSignedLogRoot().GetLogRoot(),
		}

		raw_entry, err := json.Marshal(pirEntry)
		if err != nil {
			return nil, err
		}

		padded_entry, err := PadEntry(raw_entry)
		if err != nil {
			return nil, err
		}

		flat_db = append(flat_db, padded_entry)
	}

	return flat_db, nil
}

func PadEntry(entry []byte) ([]byte, error) {
	if len(entry)+LengthPrefixBytes > EntrySizeBytes {
		return nil, fmt.Errorf("Record of %d bytes (+%d-byte length prefix) exceeds item_size_bytes=%d", len(entry), LengthPrefixBytes, EntrySizeBytes)
	}

	lengthPrefix := make([]byte, LengthPrefixBytes)
	binary.BigEndian.PutUint32(lengthPrefix, uint32(len(entry)))
	body := append(lengthPrefix, entry...)
	padding := make([]byte, EntrySizeBytes-len(body))
	return append(body, padding...), nil
}
