// Copyright 2010 Florian Duraffourg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openid

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

func Yadis(ID string) (io.Reader, error) {
	return YadisVerbose(ID, nil)
}

func YadisVerbose(ID string, verbose *log.Logger) (io.Reader, error) {
	r, err := YadisRequest(ID, "GET")
	if err != nil || r == nil {
		return nil, err
	}

	var contentType = r.Header.Get("Content-Type")

	// If it is an XRDS document, return the Reader
	if strings.HasPrefix(contentType, "application/xrds+xml") {
		if verbose != nil {
			verbose.Printf("got xrds from \"%s\"", ID)
		}
		return r.Body, nil
	}

	// If it is an HTML doc search for meta tags
	if bytes.Equal([]byte(contentType), []byte("text/html")) {
		url_, err := searchHTMLMetaXRDS(r.Body)
		if err != nil {
			return nil, err
		}
		if verbose != nil {
			verbose.Printf("fetching xrds found in html \"%s\"", url_)
		}
		return Yadis(url_)
	}

	// If the response contain an X-XRDS-Location header
	var xrds_location = r.Header.Get("X-Xrds-Location")
	if len(xrds_location) > 0 {
		if verbose != nil {
			verbose.Printf("fetching xrds found in http header \"%s\"", xrds_location)
		}
		return Yadis(xrds_location)
	}

	if verbose != nil {
		verbose.Printf("Yadis fails out, nothing found. status=%#v", r.StatusCode)
	}
	// If nothing is found try to parse it as a XRDS doc
	return nil, nil
}

func YadisRequest(url_ string, method string) (resp *http.Response, err error) {
	resp = nil

	var request = new(http.Request)
	var client = new(http.Client)
	var Header = make(http.Header)

	request.Method = method

	request.URL, err = url.Parse(url_)
	if err != nil {
		return
	}

	// Common parameters
	request.Proto = "HTTP/1.0"
	request.ProtoMajor = 1
	request.ProtoMinor = 0
	request.ContentLength = 0
	request.Close = true

	Header.Add("Accept", "application/xrds+xml")
	request.Header = Header

	// Follow a maximum of 5 redirections
	for i := 0; i < 5; i++ {
		response, err := client.Do(request)

		if err != nil {
			return nil, err
		}
		if response.StatusCode == 301 || response.StatusCode == 302 || response.StatusCode == 303 || response.StatusCode == 307 {
			location := response.Header.Get("Location")
			request.URL, err = url.Parse(location)
			if err != nil {
				return nil, err
			}
		} else {
			return response, nil
		}
	}
	return nil, errors.New("Too many redirections")
}

var (
	metaRE = regexp.MustCompile("(?i)<[ \t]*meta[^>]*http-equiv=[\"']x-xrds-location[\"'][^>]*>")
	xrdsRE = regexp.MustCompile("(?i)content=[\"']([^\"']+)[\"']")
)

func searchHTMLMetaXRDS(r io.Reader) (string, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}
	part := metaRE.Find(data)
	if part == nil {
		return "", errors.New("No -meta- match")
	}
	content := xrdsRE.FindSubmatch(part)
	if content == nil {
		return "", errors.New("No content in meta tag: " + string(part))
	}
	return string(content[1]), nil
}
