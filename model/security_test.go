// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
	"testing"
)

func TestSecurityQuestion(t *testing.T) {
	db, err := newTestDB()
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.FetchAnswer("usernotexist")
	if err != ErrNotFound {
		t.Error(err)
	}

	uid := "mokeytestuser"
	ans := "secret answer"
	questions, err := db.FetchQuestions()
	if err != nil {
		t.Fatal(err)
	}

	if len(questions) == 0 {
		t.Fatal("No questions found")
	}

	quest := questions[0]

	err = db.StoreAnswer(uid, ans, quest.ID)
	if err != nil {
		t.Error(err)
	}

	sa, err := db.FetchAnswer(uid)
	if err != nil {
		t.Error(err)
	}

	if sa.QuestionID != quest.ID {
		t.Errorf("Incorrect question ID: got %d should be %d", sa.QuestionID, quest.ID)
	}

	if sa.Question != quest.Question {
		t.Errorf("Incorrect question: got %s should be %s", sa.Question, quest.Question)
	}

	if !sa.Verify(ans) {
		t.Errorf("Failed to verify answer")
	}

	err = db.RemoveAnswer(uid)
	if err != nil {
		t.Error(err)
	}

	_, err = db.FetchAnswer(uid)
	if err != ErrNotFound {
		t.Error(err)
	}
}
