package run

import (
	"fmt"
	"os"
	"syscall"

	"github.com/kubetrail/passwd-lock/pkg/crypto"
	"github.com/kubetrail/passwd-lock/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

func Decrypt(cmd *cobra.Command, args []string) error {
	_ = viper.BindPFlag(flags.Plaintext, cmd.Flags().Lookup(flags.Plaintext))
	_ = viper.BindPFlag(flags.Ciphertext, cmd.Flags().Lookup(flags.Ciphertext))

	plaintext := viper.GetString(flags.Plaintext)
	ciphertext := viper.GetString(flags.Ciphertext)

	if len(ciphertext) == 0 {
		return fmt.Errorf("please input a ciphertext filename")
	}

	if len(plaintext) == 0 {
		plaintext = fmt.Sprintf("%s.plaintext", ciphertext)
	}

	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter password used during encryption: "); err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	encryptionKey, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read encryption password from input: %w", err)
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout()); err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	key, err := crypto.NewAesKeyFromPassphrase(encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to generate new AES key: %w", err)
	}

	b, err := os.ReadFile(ciphertext)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", ciphertext, err)
	}

	b, err = crypto.DecryptWithAesKey(b, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt input: %w", err)
	}

	if err := os.WriteFile(plaintext, b, 0600); err != nil {
		return fmt.Errorf("failed to write plaintext file: %w", err)
	}

	return nil
}
