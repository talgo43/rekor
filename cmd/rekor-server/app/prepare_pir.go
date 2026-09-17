package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/trillian/types"
	"github.com/sigstore/rekor/cmd/rekor-cli/app/format"
	internalclient "github.com/sigstore/rekor/internal/trillianclient"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pirsnapshot"
	"github.com/sigstore/rekor/pkg/trillianclient"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
)

type pirFlatLog struct {
	LogEnries [][]byte `json:"logEntries"`
}

var preparePIRCmd = &cobra.Command{
	Use:     "prepare-pir",
	Example: `  rekor-server prepare-pir`,
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
	address := viper.GetString("trillian_log_server.address")
	port := uint16(viper.GetUint16("trillian_log_server.port"))
	treeID, err := GetTreeID(cmd)
	if err != nil {
		return nil, err
	}

	cm := trillianclient.NewClientManager(nil, trillianclient.GRPCConfig{
		Address: address,
		Port:    port,
	})
	tc, err := cm.GetClient(treeID)
	if err != nil {
		return nil, err
	}

	treeSize, err := GetTreeSize(cmd, tc)
	if err != nil {
		return nil, err
	}

	logEntries, err := pirsnapshot.ExportLogEntries(cmd.Context(), tc, treeSize)
	if err != nil {
		return nil, err
	}

	err = pirsnapshot.VerifyExportedLogEntries(cmd.Context(), logEntries)
	if err != nil {
		return nil, err
	}

	flat_log, err := pirsnapshot.FlattenForPIR(cmd.Context(), logEntries)
	if err != nil {
		return nil, err
	}

	return flat_log, nil
}

func GetTreeID(cmd *cobra.Command) (int64, error) {
	treeID := viper.GetInt64("trillian_log_server.tlog_id")
	if treeID == 0 {
		return 0, fmt.Errorf("No tree ID specified, please set trillian_log_server.tlog_id")
	}

	return treeID, nil
}

func GetTreeSize(cmd *cobra.Command, tc internalclient.Client) (int64, error) {
	resp := tc.GetLatest(cmd.Context())
	if resp.Status != codes.OK {
		return 0, fmt.Errorf("Failed to get latest from trillian client, status: %s", resp.Status.String())
	}

	root := &types.LogRootV1{}
	err := root.UnmarshalBinary(resp.GetLatestResult.SignedLogRoot.LogRoot)
	if err != nil {
		return 0, err
	}

	return int64(root.TreeSize), nil
}

func init() {
	rootCmd.AddCommand(preparePIRCmd)
}
