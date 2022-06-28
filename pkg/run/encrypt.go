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

type output struct {
	Memo       string `json:"memo,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
}

func Encrypt(cmd *cobra.Command, args []string) error {
	_ = viper.BindPFlag(flags.Plaintext, cmd.Flag(flags.Plaintext))
	_ = viper.BindPFlag(flags.Ciphertext, cmd.Flag(flags.Ciphertext))
	_ = viper.BindPFlag(flags.Passphrase, cmd.Flag(flags.Passphrase))
	_ = viper.BindPFlag(flags.Memo, cmd.Flag(flags.Memo))

	plaintext := viper.GetString(flags.Plaintext)
	ciphertext := viper.GetString(flags.Ciphertext)
	passphrase := viper.GetString(flags.Passphrase)
	memo := viper.GetString(flags.Memo)

	var b []byte
	var err error

	if len(plaintext) == 0 {
		return fmt.Errorf("please input a plaintext filename")
	}

	if len(ciphertext) == 0 {
		ciphertext = fmt.Sprintf("%s.ciphertext", plaintext)
	}

	prompt, err := prompts.Status()
	if err != nil {
		return fmt.Errorf("failed to get prompt status: %w", err)
	}

	if len(passphrase) == 0 {
		passphrase, err = passphrases.New(cmd.OutOrStdout())
		if err != nil {
			return fmt.Errorf("failed to read passphrase: %w", err)
		}
	}

	key, err := crypto.NewAesKeyFromPassphrase([]byte(passphrase))
	if err != nil {
		return fmt.Errorf("failed to generate new AES key: %w", err)
	}

	if plaintext == "-" {
		if prompt {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter plaintext: "); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}

		input, err := keys.Read(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("failed to read key input: %w", err)
		}
		b = []byte(input)
	} else {
		b, err = os.ReadFile(plaintext)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", plaintext, err)
		}
	}

	b, err = crypto.EncryptWithAesKey([]byte(b), key)
	if err != nil {
		return fmt.Errorf("failed to encrypt input: %w", err)
	}

	out := &output{
		Memo:       memo,
		Ciphertext: hex.EncodeToString(b),
	}

	jb, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("failed to serialize output: %w", err)
	}

	if ciphertext == "-" {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(jb)); err != nil {
			return fmt.Errorf("failed to write to output: %w", err)
		}
	} else {
		jb = append(jb, '\n')
		if err := os.WriteFile(ciphertext, jb, 0600); err != nil {
			return fmt.Errorf("failed to write ciphertext file: %w", err)
		}
	}

	return nil
}
