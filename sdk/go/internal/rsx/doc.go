// Package rsx is the pure-Go implementation of Red-SecretsXAI (librsx).
//
// Every primitive is implemented here from its specification; the package uses no
// crypto/* packages and no third-party code, and builds with CGO_ENABLED=0. Wire
// formats are byte-for-byte compatible with the C++ librsx (see internal/format.md).
package rsx
