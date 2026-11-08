// Package report renders scan results as JSON, as text and as Windows
// Event Log entries. Every string is masked before it leaves the process.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"detectoragent/internal/model"
	"detectoragent/internal/redact"
)

// Sanitize masks secrets in every free-text field of the report.
func Sanitize(r *model.Report) {
	for i := range r.Findings {
		f := &r.Findings[i]
		for j := range f.Evidence {
			e := &f.Evidence[j]
			e.Detail = redact.String(e.Detail)
			e.Path = redact.String(e.Path)
			e.Cmdline = redact.String(e.Cmdline)
		}
	}
	for i := range r.Errors {
		r.Errors[i] = redact.String(r.Errors[i])
	}
}

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r *model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// WriteText writes a human-readable summary of the report.
func WriteText(w io.Writer, r *model.Report) error {
	fmt.Fprintf(w, "%s %s  catalog %s\n", r.Product, r.Version, r.CatalogVersion)
	fmt.Fprintf(w, "Host: %s   Run as: %s   Elevated: %v   Duration: %d ms\n", r.Host, r.RunAs, r.Elevated, r.DurationMs)
	s := r.Summary
	fmt.Fprintf(w, "Findings: %d (active %d, recent %d, installed %d, residue %d)   Not approved: %d   Actionable: %d\n",
		s.Findings, s.Active, s.Recent, s.Installed, s.Residue, s.NotApproved, s.Actionable)
	for _, c := range r.Coverage {
		fmt.Fprintf(w, "Coverage: %s\n", c)
	}
	for _, e := range r.Errors {
		fmt.Fprintf(w, "Error: %s\n", e)
	}
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "\nNo AI tool detected.")
		return nil
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "LEVEL\tCONFIDENCE\tAPPROVED\tTOOL\tCATEGORY\tUSER")
	for _, f := range r.Findings {
		user := f.User
		if user == "" {
			user = "(machine)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", f.Level, f.Confidence, yesNo(f.Approved), f.ToolName, f.Category, user)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(w, "\nEvidence:")
	for _, f := range r.Findings {
		fmt.Fprintf(w, "\n  %s [%s, %s]\n", f.ToolName, f.Level, f.Confidence)
		for i, e := range f.Evidence {
			if i == 6 {
				fmt.Fprintf(w, "    ... %d more\n", len(f.Evidence)-i)
				break
			}
			fmt.Fprintf(w, "    - %s: %s\n", e.Kind, oneLine(e.Detail))
		}
	}
	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, "\n", " ")
}
