package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/sigstore/rekor/cmd/rekor-cli/app/format"
	"github.com/sigstore/rekor/pkg/client"
	rclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	PIRFlagRekorServerURL = "pir.rekor_server_url"
)

type pirFlatLog struct {
	LogEnries [][]byte `json:"logEntries"`
}

type PIRPrepareCmdOutput struct {
	Success bool
}

func (p *PIRPrepareCmdOutput) String() string {
	if p.Success {
		return "pir-prepare completed successfully"
	}

	return "pir-prepare didn't completed successfully"
}

var PIRPrepareCmd = &cobra.Command{
	Use:     "pir-prepare",
	Example: `  rekor-server pir-prepare --pir.rekor_server_url <rekor_server_url>`,
	Short:   "Rekor prepare PIR command",
	Long:    `Publish the log entries to the PIR service`,
	PreRun: func(cmd *cobra.Command, _ []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.CliLogger.Fatalf("Error initializing cmd line args: %w", err)
		}
	},
	Run: format.WrapCmd(func(cmd *cobra.Command, _ []string) (interface{}, error) {

		log.ConfigureLogger(viper.GetString("log_type"), viper.GetString("trace-string-prefix"))
		rekorServerUrl := viper.GetString(PIRFlagRekorServerURL)

		authEntries, err := GetAuthEntries(cmd, rekorServerUrl)
		if err != nil {
			return nil, err
		}

		flatLog, err := pir.GetFlattenLog(cmd.Context(), authEntries)
		if err != nil {
			return nil, err
		}

		err = PublishFlattenLog(cmd, flatLog)
		if err != nil {
			return nil, err
		}

		return &PIRPrepareCmdOutput{Success: true}, nil
	}),
}

func PublishFlattenLog(cmd *cobra.Command, flatLog [][]byte) error {
	request, err := BuildPrepareRequest(cmd, flatLog)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: pir.PIRServiceTimeout}
	response, err := client.Do(request)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("pir_service %s failed with status %d", pir.PIRServicePreparePath, response.StatusCode)
	}

	return nil
}

func BuildPrepareRequest(cmd *cobra.Command, flatLog [][]byte) (*http.Request, error) {
	payload := pirFlatLog{
		LogEnries: flatLog,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	pirPrepareURL := fmt.Sprint(pir.PIRServiceHost, ":", pir.PIRServicePort, pir.PIRServicePreparePath)
	request, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, pirPrepareURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/json")
	return request, nil
}

func GetAuthEntries(cmd *cobra.Command, serverURL string) ([]*pir.AuthenticatedEntry, error) {
	rekorClient, err := client.GetRekorClient(serverURL)
	if err != nil {
		return nil, err
	}

	authEntries := []*pir.AuthenticatedEntry{}
	treeSize, err := GetTreeSize(cmd, rekorClient)
	if err != nil {
		return nil, err
	}

	for i := int64(0); i < treeSize; i++ {
		entry, err := GetLogEntryByIndex(cmd, rekorClient, i)
		if err != nil {
			return nil, err
		}

		authEntry, err := pir.AuthEntryFromEntryAnon(&entry)
		if err != nil {
			return nil, err
		}

		err = pir.VerifyAuthenticatedEntry(authEntry)
		if err != nil {
			return nil, err
		}

		authEntries = append(authEntries, authEntry)
	}

	return authEntries, nil
}

func GetLogEntryByIndex(cmd *cobra.Command, rekorClient *rclient.Rekor, index int64) (models.LogEntryAnon, error) {
	getEntryParams := entries.NewGetLogEntryByIndexParams().WithLogIndex(index)
	resp, err := rekorClient.Entries.GetLogEntryByIndexContext(cmd.Context(), getEntryParams)
	if err != nil {
		return models.LogEntryAnon{}, err
	}

	if len(resp.Payload) > 1 {
		return models.LogEntryAnon{}, fmt.Errorf("Expected a single entry at index %d", index)
	}

	for _, entry := range resp.Payload {
		return entry, nil
	}

	return models.LogEntryAnon{}, fmt.Errorf("No entries returned from log at index %d", index)
}

func GetTreeSize(cmd *cobra.Command, rekorClient *rclient.Rekor) (int64, error) {
	infoParams := tlog.NewGetLogInfoParams()
	result, err := rekorClient.Tlog.GetLogInfoContext(cmd.Context(), infoParams)
	if err != nil {
		return 0, err
	}

	logInfo := result.GetPayload()
	return *logInfo.TreeSize, nil
}

func init() {
	PIRPrepareCmd.Flags().String(PIRFlagRekorServerURL, "http://localhost:3000", "Address of rekor server to call")
	rootCmd.AddCommand(PIRPrepareCmd)
}
