package app

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sigstore/rekor/cmd/rekor-cli/app/format"
	"github.com/sigstore/rekor/pkg/log"
)

type pirEntry struct {
	Leaf  string   `json:"leaf"`
	Proof []string `json:"proof"`
	Root  string   `json:"root"`
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

func validateIndexFlag() error {
	if viper.GetString("log-index") == "" {
		return errors.New("'log-index' must be specified")
	}

	return nil
}

var pirQueryCmd = &cobra.Command{
	Use:     "pir-query",
	Example: `  rekor-cli pir-query --log-index <entry-index>`,
	Short:   "Rekor pir-query command",
	Long:    `Query the Rekor log to retrieve an entry proof, using PIR query `,
	PreRun: func(cmd *cobra.Command, _ []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.CliLogger.Fatalf("Error initializing cmd line args: %w", err)
		}
		if err := validateIndexFlag(); err != nil {
			log.CliLogger.Error(err)
			_ = cmd.Help()
			os.Exit(1)
		}
	},
	Run: format.WrapCmd(func(cmd *cobra.Command, _ []string) (interface{}, error) {
		log.ConfigureLogger(viper.GetString("log_type"), viper.GetString("trace-string-prefix"))

		index := viper.GetString("log-index")

		pythonCmd := exec.Command("python", "../Privacy-and-Networks-Final-Project/FinalProjectCode/test_pir_service.py", "--index", index)
		b, err := pythonCmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("pir-query script failed: %w (output: %s)", err, b)
		}

		log.CliLogger.Infof(string(b))
		result := pirEntry{}
		err = json.Unmarshal(b, &result)
		if err != nil {
			return nil, err
		}

		output := PIRQueryCmdOutput{}
		output.Leaf, err = base64.StdEncoding.DecodeString(string(result.Leaf))
		if err != nil {
			return nil, err
		}

		for _, raw_proof := range result.Proof {
			proof, err := base64.StdEncoding.DecodeString(string(raw_proof))
			output.Proof = append(output.Proof, proof)
			if err != nil {
				return nil, err
			}
		}

		output.Root, err = base64.StdEncoding.DecodeString(string(result.Root))
		if err != nil {
			return nil, err
		}

		return &output, nil
	}),
}

func init() {
	initializePFlagMap()
	if err := addLogIndexFlag(pirQueryCmd, false); err != nil {
		log.CliLogger.Fatal("Error parsing cmd line args:", err)
	}

	rootCmd.AddCommand(pirQueryCmd)
}
