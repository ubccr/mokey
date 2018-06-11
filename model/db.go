// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
	"errors"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type Datastore interface {
	// API Key
	RandKey() (string, error)
	FetchApiKeys(uid string) ([]*ApiKey, error)
	FetchApiKey(key string) (*ApiKey, error)
	CreateApiKey(uid, clientID, scopes string) (*ApiKey, string, error)
	RefreshApiKey(ak *ApiKey) error
	DestroyApiKey(user, clientID string)
	DestroyApiKeys(uid string) error

	// Token
	RandToken() (string, error)
	SignToken(salt, token string) string
	VerifyToken(salt, signedToken string) (string, bool)
	FetchTokenByUser(uid string, maxAge int) (*Token, error)
	FetchToken(token string, maxAge int) (*Token, error)
	CreateToken(uid, email string) (*Token, error)
	IncrementToken(token string) error
	DestroyToken(token string) error
	DestroyTokenByUser(uid string) error

	// Security Question
	FetchAnswer(uid string) (*SecurityAnswer, error)
	StoreAnswer(user, ans string, qid int)
	FetchQuestions() ([]*SecurityQuestion, error)
	RemoveAnswer(uid string) error
}

type DB struct {
	*sqlx.DB
}

var ErrNotFound = errors.New("Record not found in database")

func NewDB(driver, dsn string) (*DB, error) {
	db, err := sqlx.Open(driver, dsn)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return &DB{db}, nil
}
