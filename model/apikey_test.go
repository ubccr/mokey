// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
	"testing"
)

func TestApiKey(t *testing.T) {
	db, err := newTestDB()
	if err != nil {
		t.Fatal(err)
	}

	nokeys, err := db.FetchApiKeys("usernotexist")
	if err != nil {
		t.Error(err)
	}

	if len(nokeys) != 0 {
		t.Errorf("Incorrect number of keys: got %d should be %d", len(nokeys), 0)
	}

	_, err = db.FetchApiKey("nokey")
	if err != ErrNotFound {
		t.Error(err)
	}

	uid := "mokeytestuser"
	clientID := "cli"
	scopes := "openid"

	key, secret, err := db.CreateApiKey(uid, clientID, scopes)
	if err != nil {
		t.Error(err)
	}

	keys, err := db.FetchApiKeys(uid)
	if err != nil {
		t.Error(err)
	}

	if len(keys) != 1 {
		t.Errorf("Incorrect number of keys: got %d should be %d", len(keys), 1)
	}

	ak := keys[0]

	if ak.Key != key.Key {
		t.Errorf("Incorrect key: got %s should be %s", ak.Key, key.Key)
	}

	err = db.RefreshApiKey(ak)
	if err != nil {
		t.Error(err)
	}

	ak2, err := db.FetchApiKey(secret)
	if err != nil {
		t.Error(err)
	}

	if ak2.ClientID != clientID {
		t.Errorf("Incorrect clientID: got %s should be %s", ak2.ClientID, clientID)
	}

	if ak2.Scopes != scopes {
		t.Errorf("Incorrect scopes: got %s should be %s", ak2.Scopes, scopes)
	}

	err = db.DestroyApiKey(uid, ak.ClientID)
	if err != nil {
		t.Error(err)
	}

	nokeys, err = db.FetchApiKeys(uid)
	if err != nil {
		t.Error(err)
	}

	if len(nokeys) != 0 {
		t.Errorf("Incorrect number of keys: got %d should be %d", len(nokeys), 0)
	}
}
