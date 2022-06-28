package run

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/kubetrail/bip32/pkg/keys"
	"github.com/kubetrail/bip39/pkg/passphrases"
	"github.com/kubetrail/bip39/pkg/prompts"
	"github.com/kubetrail/passwd-lock/pkg/crypto"
	"github.com/kubetrail/passwd-lock/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func Decrypt(cmd *cobra.Command, args []string) error {
	_ = viper.BindPFlag(flags.Plaintext, cmd.Flags().Lookup(flags.Plaintext))
	_ = viper.BindPFlag(flags.Ciphertext, cmd.Flags().Lookup(flags.Ciphertext))
	_ = viper.BindPFlag(flags.Passphrase, cmd.Flag(flags.Passphrase))

	plaintext := viper.GetString(flags.Plaintext)
	ciphertext := viper.GetString(flags.Ciphertext)
	passphrase := viper.GetString(flags.Passphrase)

	var b []byte
	var input string
	var err error

	if len(ciphertext) == 0 {
		return fmt.Errorf("please input a ciphertext filename")
	}

	if len(plaintext) == 0 {
		plaintext = fmt.Sprintf("%s.plaintext", ciphertext)
	}

	prompt, err := prompts.Status()
	if err != nil {
		return fmt.Errorf("failed to get prompt status: %w", err)
	}

	if len(passphrase) == 0 {
		passphrase, err = passphrases.Prompt(cmd.OutOrStdout())
		if err != nil {
			return fmt.Errorf("failed to prompt for passphrase: %w", err)
		}
	}

	key, err := crypto.NewAesKeyFromPassphrase([]byte(passphrase))
	if err != nil {
		return fmt.Errorf("failed to generate new AES key: %w", err)
	}

	if ciphertext == "-" {
		if prompt {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter ciphertext: "); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}

		input, err = keys.Read(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("failed to read ciphertext from input: %w", err)
		}
	} else {
		b, err = os.ReadFile(ciphertext)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", ciphertext, err)
		}

		input = string(b)
	}

	b, err = hex.DecodeString(input)
	if err != nil {
		err1 := err
		out := &output{}
		if err := json.Unmarshal([]byte(input), out); err != nil {
			return fmt.Errorf("failed to decode input as hex string or json: %v, %v", err1, err)
		}

		b, err = hex.DecodeString(out.Ciphertext)
		if err != nil {
			return fmt.Errorf("failed to decode ciphertext as hex in json input: %w", err)
		}
	}

	b, err = crypto.DecryptWithAesKey(b, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt input: %w", err)
	}

	if plaintext == "-" {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(b)); err != nil {
			return fmt.Errorf("failed to write to output: %w", err)
		}
	} else {
		if err := os.WriteFile(plaintext, b, 0600); err != nil {
			return fmt.Errorf("failed to write plaintext file: %w", err)
		}
	}

	return nil
}
