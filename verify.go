// Copyright 2010 Florian Duraffourg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openid

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/url"
	"regexp"
)

// Verify that the url given match a successfull authentication.
//
// Return:
// 	* true if authenticated, false otherwise
// 	* the claimed identifier if authenticated
// 	* eventually an error
func Verify(url_ string) (granted bool, identifier string, err error) {

	values, err := url.ParseQuery(url_)
	if err != nil {
		return false, "", err
	}

	// The value of "openid.return_to" matches the URL of the current request (Section 11.1)
	// To be implemented in a global way

	// Discovered information matches the information in the assertion (Section 11.2)

	// An assertion has not yet been accepted from this OP with the same value for
	// "openid.response_nonce" (Section 11.3)

	// The signature on the assertion is valid and all fields that are required to be signed
	// are signed (Section 11.4)

	return VerifyValues(values)
}

var reVerifyDirectIsValid = "is_valid:true"
var reVerifyDirectNs = regexp.MustCompile("ns:([a-zA-Z0-9:/.]*)")

// Like Verify on a parsed URL
func VerifyValues(values url.Values) (granted bool, identifier string, err error) {

	// Create the url
	urlEndPoint := values.Get("openid.op_endpoint")
	if urlEndPoint == "" {
		log.Printf("no openid.op_endpoint")
		return false, "", errors.New("no openid.op_endpoint")
	}

	postArgs := url.Values(map[string][]string{})
	for k, v := range values {
		postArgs[k] = v
	}
	postArgs.Set("openid.mode", "check_authentication")

	// Post the request
	client := http.Client{}
	postReader := bytes.NewBuffer([]byte(postArgs.Encode()))
	response, err := client.Post(urlEndPoint, "application/x-www-form-urlencoded", postReader)
	if err != nil {
		log.Printf("VerifyValues failed at post")
		return false, "", err
	}

	// Parse the response
	// Convert the reader
	// We limit the size of the response to 1024 bytes but it should be large enough for most cases
	buffer := make([]byte, 1024)
	_, err = response.Body.Read(buffer)
	if err != nil {
		log.Printf("VerifyValues failed reading response")
		return false, "", err
	}

	// Check for ns
	rematch := reVerifyDirectNs.FindSubmatch(buffer)
	if rematch == nil {
		return false, "", errors.New("VerifyValues: ns value not found on the response of the OP")
	}
	nsValue := string(rematch[1])
	if nsValue != "http://specs.openid.net/auth/2.0" {
		return false, "", errors.New("VerifyValues: ns value not correct: " + nsValue)
	}

	// Check for is_valid
	match, err := regexp.Match(reVerifyDirectIsValid, buffer)
	if err != nil {
		return false, "", err
	}
	if !match {
		log.Printf("no is_valid:true in \"%s\"", buffer)
	}

	identifier = values.Get("openid.claimed_id")
	return match, identifier, nil
}
