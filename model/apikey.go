// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"time"
)

type ApiKey struct {
	UserName     string     `db:"user_name"`
	Key          string     `db:"api_key"`
	ClientID     string     `db:"client_id"`
	Scopes       string     `db:"scopes"`
	CreatedAt    *time.Time `db:"created_at"`
	LastAccessed *time.Time `db:"last_accessed"`
}

func (db *DB) RandKey() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (db *DB) FetchApiKeys(uid string) ([]*ApiKey, error) {
	keys := []*ApiKey{}
	err := db.Select(&keys, `
    select
        user_name,
        api_key,
        client_id,
        scopes,
        created_at,
        last_accessed
    from api_key where user_name = ?`, uid)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}

	return keys, nil
}

func (db *DB) FetchApiKey(key string) (*ApiKey, error) {
	h := sha256.Sum256([]byte(key))
	hash := base64.StdEncoding.EncodeToString(h[:])

	a := ApiKey{}
	err := db.Get(&a, `
    select
        user_name,
        api_key,
        client_id,
        scopes,
        created_at,
        last_accessed
    from api_key where api_key = ?`, hash)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}

	return &a, nil
}

func (db *DB) CreateApiKey(uid, clientID, scopes string) (*ApiKey, string, error) {
	key, err := db.RandKey()
	if err != nil {
		return nil, "", err
	}

	h := sha256.Sum256([]byte(key))
	hash := base64.StdEncoding.EncodeToString(h[:])

	a := ApiKey{
		UserName: uid,
		ClientID: clientID,
		Scopes:   scopes,
		Key:      string(hash)}

	_, err = db.NamedExec(`
        replace into api_key 
            (user_name,api_key,client_id,scopes,created_at,last_accessed)
        values (:user_name, :api_key, :client_id, :scopes, now(), now())`, a)
	if err != nil {
		return nil, "", err
	}

	return &a, key, nil
}

func (db *DB) RefreshApiKey(ak *ApiKey) error {
	_, err := db.NamedExec(`
        update api_key set
          last_accessed = now()
        where user_name = :user_name and api_key = :api_key`, ak)

	if err == sql.ErrNoRows {
		return ErrNotFound
	} else if err != nil {
		return err
	}

	return nil
}

func (db *DB) DestroyApiKey(user, clientID string) error {
	_, err := db.Exec("delete from api_key where user_name = ? and client_id = ?", user, clientID)

	if err == sql.ErrNoRows {
		return ErrNotFound
	} else if err != nil {
		return err
	}

	return nil
}

func (db *DB) DestroyApiKeys(uid string) error {
	_, err := db.Exec("delete from api_key where user_name = ?", uid)

	if err == sql.ErrNoRows {
		return ErrNotFound
	} else if err != nil {
		return err
	}

	return nil
}
