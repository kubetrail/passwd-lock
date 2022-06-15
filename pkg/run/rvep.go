package run

import (
	"fmt"
	"io"

	"github.com/kubetrail/bip39/pkg/passphrases"
	"github.com/spf13/cobra"
)

func Rvep(cmd *cobra.Command, args []string) error {
	passphrase, err := passphrases.New(io.Discard)
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}

	if _, err := fmt.Fprint(cmd.OutOrStdout(), passphrase); err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	return nil
}
