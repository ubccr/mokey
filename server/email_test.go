// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestWriteBase64Wrapped(t *testing.T) {
	// ~3KB of data produces a base64 payload well over the RFC 5322 998 limit
	// when written as a single line.
	data := bytes.Repeat([]byte("mokey-logo-line-test-"), 150)

	var buf bytes.Buffer
	writeBase64Wrapped(&buf, data)

	out := buf.String()
	if !strings.HasSuffix(out, "\r\n") {
		t.Fatal("expected trailing CRLF")
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(out, "\r\n", ""))
	if err != nil {
		t.Fatalf("decode wrapped base64: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatal("decoded payload does not match input")
	}

	for i, line := range strings.Split(strings.TrimSuffix(out, "\r\n"), "\r\n") {
		if len(line) > 76 {
			t.Fatalf("line %d length %d exceeds MIME base64 wrap of 76", i+1, len(line))
		}
		if len(line) > 998 {
			t.Fatalf("line %d length %d exceeds RFC 5322 limit of 998", i+1, len(line))
		}
	}
}
