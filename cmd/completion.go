package cmd

import (
	"strings"

	"github.com/spf13/cobra"
)

// registerScanCompletions teaches the shell the fixed value sets for the scan
// flags, so completing one offers the names rather than falling back to
// filenames. Registration fails only on a flag that does not exist or one
// already registered, both of which are mistakes in this file rather than
// anything a user can cause, so the error is discarded.
func (a *App) registerScanCompletions(c *cobra.Command) {
	_ = c.RegisterFlagCompletionFunc("scanner",
		func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return filterByPrefix(scannerNames(), toComplete), cobra.ShellCompDirectiveNoFileComp
		})
	_ = c.RegisterFlagCompletionFunc("output",
		func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return filterByPrefix([]string{outputText, outputPretty}, toComplete), cobra.ShellCompDirectiveNoFileComp
		})
}

// filterByPrefix returns the candidates that start with prefix, preserving
// order. An empty prefix returns every candidate.
func filterByPrefix(candidates []string, prefix string) []string {
	if prefix == "" {
		return candidates
	}
	var out []string
	for _, c := range candidates {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}
