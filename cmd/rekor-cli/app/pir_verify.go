package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sigstore/rekor/cmd/rekor-cli/app/format"
	"github.com/sigstore/rekor/pkg/client"
	rclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pir"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/rekor/pkg/verify"
)

const (
	PIRQueryRekorServerScriptPath = "../Privacy-and-Networks-Final-Project/FinalProjectCode/pir_query_rekor_server.py"
)

type pirVerifyCmdOutput struct {
	Leaf  []byte
	Proof [][]byte
	Root  []byte
}

func (p *pirVerifyCmdOutput) String() string {
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

var pirVerifyCmd = &cobra.Command{
	Use:     "pir-verify",
	Example: `  rekor-cli pir-verify --log-index <entry-index> --tree-id <tree-id>`,
	Short:   "Rekor pir-verify command",
	Long:    `Verifies an entry exists in the transparency log through an inclusion proof, USING PIR QUERY`,
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

		logIndex := viper.GetInt64("log-index")
		treeID := viper.GetInt64("tree-id")

		pirLogEntry, err := GetLogEntryByIndexWithPIR(logIndex)
		if err != nil {
			return nil, err
		}

		err = VerifyPIREntry(cmd, pirLogEntry, logIndex, treeID)
		if err != nil {
			return nil, err
		}

		output := pirVerifyCmdOutput{
			Leaf:  pirLogEntry.Leaf,
			Proof: pirLogEntry.Proof,
			Root:  pirLogEntry.Root,
		}

		return &output, nil
	}),
}

func VerifyPIREntry(cmd *cobra.Command, pirEntry pir.PIRLogEntry, logIndex int64, treeID int64) error {
	rekorClient, err := client.GetRekorClient(viper.GetString("rekor_server"), client.WithUserAgent(UserAgent()), client.WithRetryCount(viper.GetUint("retry")), client.WithLogger(log.CliLogger))
	if err != nil {
		return err
	}

	verifier, err := loadVerifier(cmd.Context(), rekorClient, strconv.FormatInt(treeID, 10))
	if err != nil {
		return err
	}

	currentSignedTreeHead, err := GetSignedHead(cmd, rekorClient)
	if err != nil {
		return err
	}

	currentCheckpoint := util.SignedCheckpoint{}
	if err := currentCheckpoint.UnmarshalText([]byte(*currentSignedTreeHead)); err != nil {
		return err
	}

	if !currentCheckpoint.Verify(verifier) {
		return errors.New("signature on tree head did not verify")
	}

	snapshotCheckpoint := util.SignedCheckpoint{}
	if err := snapshotCheckpoint.UnmarshalText([]byte(pirEntry.Checkpoint)); err != nil {
		return err
	}

	if !snapshotCheckpoint.Verify(verifier) {
		return errors.New("signature on tree head did not verify")
	}

	err = verify.ProveConsistency(cmd.Context(), rekorClient, &snapshotCheckpoint, &currentCheckpoint, strconv.FormatInt(treeID, 10))
	if err != nil {
		return err
	}

	err = verify.VerifyLogEntry(cmd.Context(), pirEntry.ToEntryAnon(logIndex), verifier)
	if err != nil {
		return err
	}

	return nil
}

func GetLogEntryByIndexWithPIR(logIndex int64) (pir.PIRLogEntry, error) {
	pirQueryCmd := exec.Command("python", PIRQueryRekorServerScriptPath, "--index", strconv.FormatInt(logIndex, 10))
	result, err := pirQueryCmd.Output()
	if err != nil {
		return pir.PIRLogEntry{}, fmt.Errorf("pir-verify command failed with: %w (result: %s)", err, result)
	}

	entry := pir.PIRLogEntry{}
	err = json.Unmarshal(result, &entry)
	if err != nil {
		return pir.PIRLogEntry{}, err
	}

	return entry, nil
}

func GetSignedHead(cmd *cobra.Command, rekorClient *rclient.Rekor) (*string, error) {
	infoParams := tlog.NewGetLogInfoParams()
	result, err := rekorClient.Tlog.GetLogInfoContext(cmd.Context(), infoParams)
	if err != nil {
		return nil, err
	}

	logInfo := result.GetPayload()
	return logInfo.SignedTreeHead, nil
}

func addTreeIDFlag(cmd *cobra.Command, required bool) error {
	return addFlagToCmd(cmd, required, uintFlag, "tree-id", "the ID of the rekor tree")
}

func init() {
	initializePFlagMap()
	if err := addLogIndexFlag(pirVerifyCmd, false); err != nil {
		log.CliLogger.Fatal("Error parsing cmd line args:", err)
	}

	if err := addTreeIDFlag(pirVerifyCmd, false); err != nil {
		log.CliLogger.Fatal("Error parsing cmd line args:", err)
	}

	rootCmd.AddCommand(pirVerifyCmd)
}
