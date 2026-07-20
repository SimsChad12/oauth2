package oauth2

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mockTokenSource struct {
	calls int32
	delay time.Duration
	err   error
	token *Token
}

func (m *mockTokenSource) Token() (*Token, error) {
	atomic.AddInt32(&m.calls, 1)
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	if m.err != nil {
		return nil, m.err
	}
	return m.token, nil
}

func TestReuseTokenSource_ConcurrentRefresh(t *testing.T) {
	mock := &mockTokenSource{
		delay: 50 * time.Millisecond,
		token: &Token{
			AccessToken:  "new-access-token",
			TokenType:    "Bearer",
			RefreshToken: "new-refresh-token",
			Expiry:       time.Now().Add(1 * time.Hour),
		},
	}

	expiredToken := &Token{
		AccessToken:  "old-access-token",
		TokenType:    "Bearer",
		RefreshToken: "old-refresh-token",
		Expiry:       time.Now().Add(-1 * time.Hour),
	}
	rts := ReuseTokenSource(expiredToken, mock)

	const numGoroutines = 15
	var wg sync.WaitGroup
	tokens := make([]*Token, numGoroutines)
	errorsList := make([]error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			tok, err := rts.Token()
			tokens[idx] = tok
			errorsList[idx] = err
		}(i)
	}
	wg.Wait()

	calls := atomic.LoadInt32(&mock.calls)
	if calls != 1 {
		t.Errorf("expected exactly 1 call to underlying TokenSource, got %d", calls)
	}

	expectedToken := mock.token
	for i, tok := range tokens {
		if errorsList[i] != nil {
			t.Errorf("goroutine %d got unexpected error: %v", i, errorsList[i])
		}
		if tok == nil {
			t.Errorf("goroutine %d got nil token", i)
			continue
		}
		if tok.AccessToken != expectedToken.AccessToken {
			t.Errorf("goroutine %d got access token %q, expected %q", i, tok.AccessToken, expectedToken.AccessToken)
		}
	}
}

func TestReuseTokenSource_ConcurrentRefreshErrorPropagation(t *testing.T) {
	expectedErr := errors.New("refresh failed")
	mock := &mockTokenSource{
		delay: 50 * time.Millisecond,
		err:   expectedErr,
	}

	expiredToken := &Token{
		AccessToken:  "old-access-token",
		TokenType:    "Bearer",
		RefreshToken: "old-refresh-token",
		Expiry:       time.Now().Add(-1 * time.Hour),
	}
	rts := ReuseTokenSource(expiredToken, mock)

	const numGoroutines = 15
	var wg sync.WaitGroup
	errorsList := make([]error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			_, err := rts.Token()
			errorsList[idx] = err
		}(i)
	}
	wg.Wait()

	calls := atomic.LoadInt32(&mock.calls)
	if calls != 1 {
		t.Errorf("expected exactly 1 call to underlying TokenSource, got %d", calls)
	}

	for i, err := range errorsList {
		if err != expectedErr {
			t.Errorf("goroutine %d got error %v, expected %v", i, err, expectedErr)
		}
	}
}