package app

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/go-openapi/swag/conv"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sigstore/rekor/cmd/rekor-cli/app/format"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/verify"
)

type pirEntry struct {
	Leaf                 []byte   `json:"leaf"`
	Proof                [][]byte `json:"proof"`
	Root                 []byte   `json:"root"`
	TreeSize             int64    `json:"treeSize"`
	Checkpoint           []byte   `json:"checkpoint"`
	SignedEntryTimestamp []byte   `json:"signedEntryTimestamp"`
	IntegratedTime       int64    `json:"integratedTime"`
	LogId                string   `json:"logId"`
}

type PIRQueryCmdOutput struct {
	Leaf  []byte
	Proof [][]byte
	Root  []byte
}

func (p *PIRQueryCmdOutput) String() string {
	s := fmt.Sprintf("Decoded Entry (%d bytes):\n%s\n\n", len(p.Leaf), p.Leaf)
	s += fmt.Sprintf("Inclusion Proof (%d hashes):\n", len(p.Proof))
	for i, h := range p.Proof {
		s += fmt.Sprintf("  [%d] %x\n", i, h)
	}
	s += fmt.Sprintf("Root Hash: %x\n", p.Root)
	return s
}

func validatePirQueryFlags() error {
	if viper.GetString("log-index") == "" {
		return errors.New("'log-index' must be specified")
	}

	if viper.GetString("tree-id") == "" {
		return errors.New("'tree-id' must be specified")
	}
	return nil
}

var pirQueryCmd = &cobra.Command{
	Use:     "pir-query",
	Example: `  rekor-cli pir-query --log-index <entry-index> --tree-id <tree-id> --rekor_server http://127.0.0.1:3000`,
	Short:   "Rekor pir-query command",
	Long:    `Query the Rekor log to retrieve an entry proof, using PIR query `,
	PreRun: func(cmd *cobra.Command, _ []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.CliLogger.Fatalf("Error initializing cmd line args: %w", err)
		}
		if err := validatePirQueryFlags(); err != nil {
			log.CliLogger.Error(err)
			_ = cmd.Help()
			os.Exit(1)
		}
	},
	Run: format.WrapCmd(func(cmd *cobra.Command, _ []string) (interface{}, error) {
		log.ConfigureLogger(viper.GetString("log_type"), viper.GetString("trace-string-prefix"))
		rekorClient, err := client.GetRekorClient(viper.GetString("rekor_server"), client.WithUserAgent(UserAgent()), client.WithRetryCount(viper.GetUint("retry")), client.WithLogger(log.CliLogger))
		if err != nil {
			return nil, err
		}

		index := viper.GetString("log-index")
		logIndexInt, err := strconv.ParseInt(index, 10, 0)
		if err != nil {
			return nil, err
		}

		treeID := viper.GetString("tree-id")
		treeIDInt, err := strconv.ParseInt(treeID, 10, 0)
		if err != nil {
			return nil, err
		}

		pythonCmd := exec.Command("python", "../Privacy-and-Networks-Final-Project/FinalProjectCode/test_pir_service.py", "--index", index)
		b, err := pythonCmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("pir-query script failed: %w (output: %s)", err, b)
		}

		result := pirEntry{}
		err = json.Unmarshal(b, &result)
		if err != nil {
			return nil, err
		}

		output := PIRQueryCmdOutput{
			Leaf:  result.Leaf,
			Proof: result.Proof,
			Root:  result.Root,
		}

		encodedHashes := []string{}
		for _, hash := range output.Proof {
			encodedHashes = append(encodedHashes, hex.EncodeToString(hash))
		}

		entry := models.LogEntryAnon{
			LogID:          &result.LogId,
			LogIndex:       &logIndexInt,
			Body:           base64.StdEncoding.EncodeToString(result.Leaf),
			IntegratedTime: &result.IntegratedTime,
			Verification: &models.LogEntryAnonVerification{
				InclusionProof: &models.InclusionProof{
					RootHash:   conv.Pointer(hex.EncodeToString(result.Root)),
					TreeSize:   conv.Pointer(result.TreeSize),
					LogIndex:   &logIndexInt,
					Hashes:     encodedHashes,
					Checkpoint: conv.Pointer(string(result.Checkpoint)),
				},
				SignedEntryTimestamp: result.SignedEntryTimestamp,
			},
		}

		verifier, err := loadVerifier(cmd.Context(), rekorClient, strconv.FormatInt(treeIDInt, 10))
		if err != nil {
			return nil, err
		}

		if err := verify.VerifyLogEntry(cmd.Context(), &entry, verifier); err != nil {
			return nil, fmt.Errorf("validating entry: %w", err)
		}

		return &output, nil
	}),
}

func addTreeIdFlag(cmd *cobra.Command, required bool) error {
	return addFlagToCmd(cmd, required, uintFlag, "tree-id", "the ID of the rekor tree")
}

func init() {
	initializePFlagMap()
	if err := addLogIndexFlag(pirQueryCmd, false); err != nil {
		log.CliLogger.Fatal("Error parsing cmd line args:", err)
	}

	if err := addTreeIdFlag(pirQueryCmd, false); err != nil {
		log.CliLogger.Fatal("Error parsing cmd line args:", err)
	}

	rootCmd.AddCommand(pirQueryCmd)
}
