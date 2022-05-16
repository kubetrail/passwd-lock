/*
Copyright © 2022 kubetrail.io authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"

	"github.com/kubetrail/passwd-lock/pkg/flags"
	"github.com/kubetrail/passwd-lock/pkg/run"
	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt data",
	Long: `This command decrypts ciphertext produced 
previously using encrypt command.`,
	RunE:    run.Decrypt,
	Example: fmt.Sprintf("%s decrypt --ciphertext sample.txt.ciphertext", run.AppName),
	Args:    cobra.ExactArgs(0),
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	f := decryptCmd.Flags()

	f.String(flags.Plaintext, "-", "Output plaintext filename")
	f.String(flags.Ciphertext, "-", "Input ciphertext filename")
	f.String(flags.Passphrase, "", "Passphrase for encryption")
}
