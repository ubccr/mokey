// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
	"crypto/rand"
	"encoding/hex"
)

func GenerateSecret(n int) (string, error) {
	secret := make([]byte, n)
	_, err := rand.Read(secret)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(secret), nil
}
