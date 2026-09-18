package app

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sigstore/rekor/cmd/rekor-cli/app/format"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pirsnapshot"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type pirFlatLog struct {
	LogEnries [][]byte `json:"logEntries"`
}

var preparePIRCmd = &cobra.Command{
	Use:     "prepare-pir",
	Example: `  rekor-server prepare-pir --prepare_pir.rekor_servre_url <rekor_server_url>`,
	Short:   "Rekor prepare PIR command",
	Long:    `Publish the log entries to the PIR manager, to be used on PIR verification`,
	PreRun: func(cmd *cobra.Command, _ []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.CliLogger.Fatalf("Error initializing cmd line args: %w", err)
		}
	},
	Run: format.WrapCmd(func(cmd *cobra.Command, _ []string) (interface{}, error) {

		log.ConfigureLogger(viper.GetString("log_type"), viper.GetString("trace-string-prefix"))

		flat_log, err := GetFlattenLog(cmd)
		if err != nil {
			return nil, err
		}

		err = PublishFlattenLog(cmd, flat_log)
		if err != nil {
			return nil, err
		}

		return nil, nil
	}),
}

func PublishFlattenLog(cmd *cobra.Command, flat_log [][]byte) error {
	payload := pirFlatLog{
		LogEnries: flat_log,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(
		cmd.Context(),
		http.MethodPost,
		"http://host.docker.internal:8787/prepare",
		bytes.NewReader(bodyBytes),
	)
	if err != nil {
		return err
	}

	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("pir_service /prepare failed with status %d", response.StatusCode)
	}

	return nil
}

func GetFlattenLog(cmd *cobra.Command) ([][]byte, error) {
	rekor_server_url := viper.GetString("prepare_pir.rekor_server_url")
	rekorClient, err := client.GetRekorClient(rekor_server_url)
	if err != nil {
		return nil, err
	}

	infoParams := tlog.NewGetLogInfoParams()
	result, err := rekorClient.Tlog.GetLogInfoContext(cmd.Context(), infoParams)
	if err != nil {
		return nil, err
	}

	logInfo := result.GetPayload()
	treeSize := logInfo.TreeSize

	authEntries := []*pirsnapshot.AuthenticatedEntry{}

	for i := int64(0); i < *treeSize; i++ {
		getEntryParams := entries.NewGetLogEntryByIndexParams().WithLogIndex(i)
		resp, err := rekorClient.Entries.GetLogEntryByIndexContext(cmd.Context(), getEntryParams)
		if err != nil {
			return nil, err
		}

		for _, entry := range resp.Payload {
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

			authEntry := pirsnapshot.AuthenticatedEntry{
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

			err = pirsnapshot.VerifyAuthenticatedEntry(authEntry)
			if err != nil {
				return nil, err
			}

			authEntries = append(authEntries, &authEntry)
		}
	}

	flat_log, err := pirsnapshot.FlattenForPIR(cmd.Context(), authEntries)
	if err != nil {
		return nil, err
	}

	return flat_log, nil
}

func init() {
	preparePIRCmd.Flags().String("prepare_pir.rekor_server_url", "http://localhost:3000", "Address of server to call")
	rootCmd.AddCommand(preparePIRCmd)
}
