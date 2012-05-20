// Copyright 2010 Florian Duraffourg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openid

import (
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

func Yadis(id string) (io.Reader, error) {
	return YadisVerbose(id, nil)
}

func YadisVerbose(id string, verbose *log.Logger) (io.Reader, error) {
	for i := 0; i < 5; i++ {
		r, err := YadisRequest(id)
		if err != nil || r == nil {
			return nil, err
		}

		body, redirect, err := YadisProcess(r, verbose)
		if err != nil {
			return body, err
		}
		if body != nil {
			if verbose != nil {
				verbose.Printf(`got xrds from "%s"`, id)
			}
			return body, nil
		}
		if redirect == "" {
			return nil, nil
		}
		id = redirect
	}
	return nil, errors.New("Too many Yadis redirects")
}

func YadisProcess(r *http.Response, verbose *log.Logger) (body io.Reader, redirect string, err error) {
	contentType := r.Header.Get("Content-Type")

	// If it is an XRDS document, return the Reader
	if strings.HasPrefix(contentType, "application/xrds+xml") {
		return r.Body, "", nil
	}

	// If it is an HTML doc search for meta tags
	if contentType == "text/html" {
		url_, err := searchHTMLMetaXRDS(r.Body)
		if err != nil {
			return nil, "", err
		}
		if verbose != nil {
			verbose.Printf(`fetching xrds found in html "%s"`, url_)
		}
		return nil, url_, nil
	}

	// If the response contain an X-XRDS-Location header
	xrds_location := r.Header.Get("X-Xrds-Location")
	if len(xrds_location) > 0 {
		if verbose != nil {
			verbose.Printf(`fetching xrds found in http header "%s"`, xrds_location)
		}
		return nil, xrds_location, nil
	}

	if verbose != nil {
		verbose.Printf("Yadis fails out, nothing found. status=%#v", r.StatusCode)
	}
	// If nothing is found try to parse it as a XRDS doc
	return nil, "", nil
}

func YadisRequest(url_ string) (*http.Response, error) {
	request := http.Request{
		Method:        "GET",
		Proto:         "HTTP/1.0",
		ProtoMajor:    1,
		ProtoMinor:    0,
		ContentLength: 0,
		Close:         true,
	}

	var err error
	request.URL, err = url.Parse(url_)
	if err != nil {
		return nil, err
	}

	header := http.Header{}
	header.Add("Accept", "application/xrds+xml")
	request.Header = header

	// Follow a maximum of 5 redirections
	client := http.Client{}
	for i := 0; i < 5; i++ {
		response, err := client.Do(&request)
		if err != nil {
			return nil, err
		}

		switch response.StatusCode {
		case 301, 302, 303, 307:
			location := response.Header.Get("Location")
			request.URL, err = url.Parse(location)
			if err != nil {
				return nil, err
			}
		default:
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
