// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package oauth2 provides support for making OAuth2 authorized HTTP requests.
// It is a low-level library with support for the authorization code flow,
// client credentials flow, implicit flow, and resource owner password credentials flow.
package oauth2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2/internal"
)

// NoContext is the default context you should use if you don't have a context.
//
// Deprecated: Use context.Background() or context.TODO() instead.
var NoContext = context.Background()

// Config describes a 3-legged OAuth2 flow, with to-be-templated
// URLs and client credentials.
type Config struct {
	// ClientID is the application's ID.
	ClientID string

	// ClientSecret is the application's secret.
	ClientSecret string

	// Endpoint contains the resource server's token endpoint
	// URLs. These are defined here and can be found in the
	// sub-packages of this package (e.g. github, google, facebook, etc).
	Endpoint Endpoint

	// RedirectURL is the URL to redirect users after authentication.
	RedirectURL string

	// Scope specifies optional requested permissions.
	Scopes []string
}

// A TokenSource is anything that can return a token.
type TokenSource interface {
	// Token returns a token or an error.
	// Token must be safe for concurrent use by multiple goroutines.
	// The returned Token must not be modified.
	Token() (*Token, error)
}

// Endpoint contains the OAuth 2.0 provider's authorization and token
// endpoint URLs.
type Endpoint struct {
	AuthURL   string
	TokenURL  string
	AuthStyle AuthStyle
}

// AuthStyle describes how the client secret is passed to the token endpoint.
type AuthStyle int

const (
	// AuthStyleAutoDetect means the style is automatically detected.
	AuthStyleAutoDetect AuthStyle = 0

	// AuthStyleInParams sends the client credentials in the HTTP request body.
	AuthStyleInParams AuthStyle = 1

	// AuthStyleInHeader sends the client credentials in the HTTP Authorization header.
	AuthStyleInHeader AuthStyle = 2
)

// AuthCodeURL returns a URL to OAuth 2.0 provider's consent page
// that asks for permissions for the required scopes state.
func (c *Config) AuthCodeURL(state string, opts ...AuthCodeOption) string {
	var buf strings.Builder
	buf.WriteString(c.Endpoint.AuthURL)
	if strings.Contains(c.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {c.ClientID},
	}
	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}
	if len(c.Scopes) > 0 {
		v.Set("scope", strings.Join(c.Scopes, " "))
	}
	if state != "" {
		v.Set("state", state)
	}
	for _, opt := range opts {
		opt.setValue(v)
	}
	buf.WriteString(v.Encode())
	return buf.String()
}

// PasswordCredentialsToken converts a resource owner username and password
// into a token.
//
// Use the credentials of the resource owner (the end-user).
func (c *Config) PasswordCredentialsToken(ctx context.Context, username, password string) (*Token, error) {
	return RetrieveToken(ctx, c.ClientID, c.ClientSecret, c.Endpoint.TokenURL, url.Values{
		"grant_type": {"password"},
		"username":   {username},
		"password":   {password},
	}, c.Endpoint.AuthStyle)
}

// Exchange converts an authorization code into a token.
func (c *Config) Exchange(ctx context.Context, code string, opts ...AuthCodeOption) (*Token, error) {
	v := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
	}
	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}
	for _, opt := range opts {
		opt.setValue(v)
	}
	return RetrieveToken(ctx, c.ClientID, c.ClientSecret, c.Endpoint.TokenURL, v, c.Endpoint.AuthStyle)
}

// Client returns an HTTP client using the provided token.
// The token will be auto-refreshed as necessary.
// The resulting client's Transport is typically *oauth2.Transport.
//
// The provided context is used for creating the Transport and for
// every subsequent token refresh request. If the context expires,
// the client's Transport will fail to retrieve a new token.
//
// The provided context is also used to retrieve the current HTTP Client
// from the context using the HTTPClient key.
func (c *Config) Client(ctx context.Context, t *Token) *http.Client {
	return NewClient(ctx, c.TokenSource(ctx, t))
}

// TokenSource returns a TokenSource that returns t until t expires,
// automatically refreshing it using c as necessary.
//
// The returned TokenSource is safe for concurrent use by multiple goroutines.
//
// The provided context is used for every subsequent token refresh request.
// If the context expires, the TokenSource will fail to retrieve a new token.
//
// The provided context is also used to retrieve the current HTTP Client
// from the context using the HTTPClient key.
func (c *Config) TokenSource(ctx context.Context, t *Token) TokenSource {
	return ReuseTokenSource(t, &tokenSource{
		ctx:  ctx,
		conf: c,
		t:    t,
	})
}

type tokenSource struct {
	ctx  context.Context
	conf *Config
	t    *Token
}

func (s *tokenSource) Token() (*Token, error) {
	if s.t == nil {
		return nil, errors.New("oauth2: token expired and no refresh token is present")
	}
	if s.t.RefreshToken == "" {
		return nil, errors.New("oauth2: token expired and no refresh token is present")
	}
	return retrieveToken(s.ctx, s.conf, s.t.RefreshToken)
}

// ReuseTokenSource returns a TokenSource that passes through to src, but keeps the
// returned token in memory and exposes it as long as the token is still valid.
//
// The returned TokenSource is safe for concurrent use by multiple goroutines.
func ReuseTokenSource(t *Token, src TokenSource) TokenSource {
	return &reuseTokenSource{
		t:   t,
		new: src,
	}
}

type reuseTokenSource struct {
	new TokenSource // new retrieves a new token

	mu sync.RWMutex // guards t and other fields
	t  *Token

	// In-flight refresh tracking
	refreshing bool
	wait       chan struct{}
	err        error
}

func (s *reuseTokenSource) Token() (*Token, error) {
	s.mu.RLock()
	if s.t.Valid() {
		t := s.t
		s.mu.RUnlock()
		return t, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	// Double check after acquiring write lock
	if s.t.Valid() {
		t := s.t
		s.mu.Unlock()
		return t, nil
	}

	if s.refreshing {
		wait := s.wait
		s.mu.Unlock()
		<-wait

		s.mu.RLock()
		defer s.mu.RUnlock()
		if s.t.Valid() {
			return s.t, nil
		}
		return nil, s.err
	}

	s.refreshing = true
	s.wait = make(chan struct{})
	s.mu.Unlock()

	t, err := s.new.Token()

	s.mu.Lock()
	s.refreshing = false
	s.err = err
	if err == nil {
		s.t = t
	}
	close(s.wait)
	s.mu.Unlock()

	return t, err
}

// HTTPClient is the context key to associate an *http.Client value with
// a context.
var HTTPClient internal.ContextKey

// An AuthCodeOption is passed to Config.AuthCodeURL.
type AuthCodeOption interface {
	setValue(url.Values)
}

type setParam struct{ k, v string }

func (p setParam) setValue(m url.Values) { m.Set(p.k, p.v) }

// SetAuthURLParam builds an AuthCodeOption which passes key/value parameters
// to a provider's authorization endpoint.
func SetAuthURLParam(key, value string) AuthCodeOption {
	return setParam{k: key, v: value}
}

// ApprovalForce forces the users to re-approve the authorization.
//
// Deprecated: Use AccessTypeOnline or AccessTypeOffline.
var ApprovalForce AuthCodeOption = setParam{"approval_prompt", "force"}

// AccessTypeOnline and AccessTypeOffline are options passed to Config.AuthCodeURL.
// They specify whether the user is prompted for offline access.
var (
	AccessTypeOnline  AuthCodeOption = setParam{"access_type", "online"}
	AccessTypeOffline AuthCodeOption = setParam{"access_type", "offline"}
)