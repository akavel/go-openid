// Copyright 2010 Florian Duraffourg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package openid implements parts of the OpenID 2.0 standard.
For more information, see: http://openid.net/specs/openid-authentication-2_0.html


Usage:

	query, err := openid.Discover("http://johnsmith.myopenid.com")
	if err != nil {
		panic(err)
	}
	url := query.CreateAuthenticationRequest("http://www.sesame.com", "/loginVerifier")

Now you have to redirect the user to the url returned. The OP (OpenID Provider) will then
forward the user back to you (i.e. in example to: "http://www.sesame.com/loginVerifier"),
after authenticating him.

To check the user's identity afterwards, run:

	grant, id, err := openid.Verify(URL)

URL is the url the user was redirected to, with the full query string.
The grant variable will be true if the user was correctly authenticated,
false otherwise.  If the user was authenticated, id contains his identifier.

*/
package openid

/*
{ClaimedID?}.Discover()
{ClaimedID, OPEndpoindURL}.BuildRedirect(realm, returnto)
id, err := {ClaimedID, OPEndpointURL}.Verify(receivedURLValues)
*/

import (
	"log"
	"net/url"
	"strings"
)

type Query struct {
	ClaimedID     string
	OPEndpointURL string
	*log.Logger
}

func (q Query) logf(format string, args ...interface{}) {
	if q.Logger == nil {
		return
	}
	q.Logger.Printf(format, args...)
}

const (
	identifierXRI = iota
	identifierURL
)

func GetRedirectURL(identifier string, realm string, returnto string) (string, error) {
	query, err := Discover(identifier)
	if err != nil {
		return "", err
	}

	// At this point we have the endpoint and eventually a claimed id
	// Create the authentication request
	return query.CreateAuthenticationRequest(realm, returnto), nil
}

func normalizeIdentifier(id string) (identifier string, identifierType int) {
	identifier = id

	// 1.  If the user's input starts with the "xri://" prefix, it MUST be stripped off,
	// so that XRIs are used in the canonical form.
	if strings.HasPrefix(identifier, "xri://") {
		identifier = identifier[6:]
	}

	// 2. If the first character of the resulting string is an XRI Global Context Symbol
	// ("=", "@", "+", "$", "!") or "(", as defined in Section 2.2.1 of [XRI_Syntax_2.0]
	// (Reed, D. and D. McAlpin, “Extensible Resource Identifier (XRI) Syntax V2.0,” .),
	// then the input SHOULD be treated as an XRI.
	var firstChar = identifier[0]
	if firstChar == '=' || firstChar == '@' || firstChar == '+' || firstChar == '$' || firstChar == '!' {
		identifierType = identifierXRI
		return
	}

	// 3. Otherwise, the input SHOULD be treated as an http URL; if it does not include
	// a "http" or "https" scheme, the Identifier MUST be prefixed with the string "http://".
	// If the URL contains a fragment part, it MUST be stripped off together with the fragment
	// delimiter character "#". See Section 11.5.2 (HTTP and HTTPS URL Identifiers) for more information.
	identifierType = identifierURL
	if !strings.HasPrefix(identifier, "http://") && !strings.HasPrefix(identifier, "https://") {
		identifier = "http://" + identifier
	}

	// 4. URL Identifiers MUST then be further normalized by both following redirects when
	// retrieving their content and finally applying the rules in Section 6 of [RFC3986]
	// (Berners-Lee, T., “Uniform Resource Identifiers (URI): Generic Syntax,” .) to the
	// final destination URL. This final URL MUST be noted by the Relying Party as the Claimed
	// Identifier and be used when requesting authentication (Requesting Authentication).

	return
}

func (q Query) CreateAuthenticationRequest(Realm, ReturnTo string) string {
	claimedID := q.ClaimedID
	if claimedID == "" {
		claimedID = "http://specs.openid.net/auth/2.0/identifier_select"
	}
	p := map[string][]string{
		"openid.ns":         []string{"http://specs.openid.net/auth/2.0"},
		"openid.mode":       []string{"checkid_setup"},
		"openid.return_to":  []string{Realm + ReturnTo},
		"openid.realm":      []string{Realm},
		"openid.claimed_id": []string{claimedID},
		"openid.identity":   []string{claimedID},
	}

	url_ := q.OPEndpointURL
	if strings.Index(url_, "?") == -1 {
		url_ = url_ + "?"
	} else {
		url_ = url_ + "&"
	}

	return url_ + url.Values(p).Encode()
}
