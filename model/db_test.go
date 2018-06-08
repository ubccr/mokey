// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
	"os"
	"testing"
)

func newTestDB() (*DB, error) {
	dsn := os.Getenv("MOKEY_TEST_DSN")
	return NewDB("mysql", dsn)
}

func TestDB(t *testing.T) {
	_, err := newTestDB()
	if err != nil {
		t.Fatal(err)
	}
}
