package run

import (
	"bytes"
	"fmt"
	"os"
	"syscall"

	"github.com/kubetrail/passwd-lock/pkg/crypto"
	"github.com/kubetrail/passwd-lock/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

func Encrypt(cmd *cobra.Command, args []string) error {
	_ = viper.BindPFlag(flags.Plaintext, cmd.Flags().Lookup(flags.Plaintext))
	_ = viper.BindPFlag(flags.Ciphertext, cmd.Flags().Lookup(flags.Ciphertext))

	plaintext := viper.GetString(flags.Plaintext)
	ciphertext := viper.GetString(flags.Ciphertext)

	if len(plaintext) == 0 {
		return fmt.Errorf("please input a plaintext filename")
	}

	if len(ciphertext) == 0 {
		ciphertext = fmt.Sprintf("%s.ciphertext", plaintext)
	}

	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter encryption password (min 8 char): "); err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	encryptionKey, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read encryption password from input: %w", err)
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout()); err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter encryption password again: "); err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	encryptionKeyConfirm, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read encryption password from input: %w", err)
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout()); err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	if !bytes.Equal(encryptionKey, encryptionKeyConfirm) {
		return fmt.Errorf("passwords do not match")
	}

	key, err := crypto.NewAesKeyFromPassphrase(encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to generate new AES key: %w", err)
	}

	b, err := os.ReadFile(plaintext)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", plaintext, err)
	}

	b, err = crypto.EncryptWithAesKey([]byte(b), key)
	if err != nil {
		return fmt.Errorf("failed to encrypt input: %w", err)
	}

	if err := os.WriteFile(ciphertext, b, 0600); err != nil {
		return fmt.Errorf("failed to write ciphertext file: %w", err)
	}

	return nil
}
