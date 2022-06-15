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
	"github.com/kubetrail/passwd-lock/pkg/run"
	"github.com/spf13/cobra"
)

// rvepCmd represents the rvep command
var rvepCmd = &cobra.Command{
	Use:   "rvep",
	Short: "Read verify and echo passwd",
	Long: `This is a command that is mainly intended to be used
to populate an environment variable with user passwd in such a way
that it does not get captured in command history.

When you run this command, it will prompt the user to enter
passwd twice, it will then verify that the passwds match,
and it will eventually echo it out.

Use it as follows:
export PASSWD=$(passwd-lock rvep)
`,
	RunE: run.Rvep,
}

func init() {
	rootCmd.AddCommand(rvepCmd)
}
