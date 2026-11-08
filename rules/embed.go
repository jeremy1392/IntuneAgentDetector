// Package rules embeds the default detection catalog.
package rules

import _ "embed"

// Default is the catalog compiled into the binary.
//
//go:embed catalog.yaml
var Default []byte
