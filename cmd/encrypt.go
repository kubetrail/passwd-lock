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

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt data",
	Long: `This command will ask for a password that will be used
to create an AES key to encrypt the data.

Create a random file:
  openssl rand -out sample.txt -base64 $(( 2**30 * 3/4 ))

Encrypt using a password as shown in example.
`,
	RunE:    run.Encrypt,
	Example: fmt.Sprintf("%s encrypt --plaintext sample.txt", run.AppName),
	Args:    cobra.ExactArgs(0),
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	f := encryptCmd.Flags()

	f.String(flags.Plaintext, "-", "Input plaintext filename")
	f.String(flags.Ciphertext, "-", "Output ciphertext filename")
	f.String(flags.Passphrase, "", "Passphrase for encryption")
	f.String(flags.Memo, "", "Memo to add to output")
}
