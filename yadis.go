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

func Discover(identifier string) (*Query, error) {
	return DiscoverVerbose(identifier, nil)
}

func DiscoverVerbose(identifier string, verbose *log.Logger) (*Query, error) {
	id, idType := normalizeIdentifier(identifier)

	// If the identifier is an XRI, [XRI_Resolution_2.0] will yield an XRDS document
	// that contains the necessary information. It should also be noted that Relying
	// Parties can take advantage of XRI Proxy Resolvers, such as the one provided by
	// XDI.org at http://www.xri.net. This will remove the need for the RPs to perform
	// XRI Resolution locally.
	if idType == identifierXRI {
		// Not implemented yet
		return nil, errors.New("XRI identifier not implemented yet")
	}

	// If it is a URL, the Yadis protocol [Yadis] SHALL be first attempted. If it succeeds,
	// the result is again an XRDS document.
	if idType == identifierURL {
		query := Query{
			Logger: verbose,
		}
		reader, err := query.yadisGet(id)
		if err != nil {
			return nil, err
		}
		if reader == nil {
			return nil, errors.New("Yadis returned an empty Reader for the ID: " + id)
		}

		err = query.parseXRDS(reader)
		if query.OPEndpointURL == "" {
			return nil, errors.New("Unable to parse the XRDS document: " + err.Error())
		}
		return &query, nil
	}

	// If the Yadis protocol fails and no valid XRDS document is retrieved, or
	// no Service Elements are found in the XRDS document, the URL is retrieved
	// and HTML-Based discovery SHALL be attempted.

	return nil, errors.New("Non-Yadis identifiers not implemented yet")
}

func (q Query) yadisGet(id string) (io.Reader, error) {
	for i := 0; i < 5; i++ {
		r, err := YadisRequest(id)
		if err != nil || r == nil {
			return nil, err
		}

		body, redirect, err := q.yadisProcess(r)
		if err != nil {
			return body, err
		}
		if body != nil {
			q.logf(`got xrds from "%s"`, id)
			return body, nil
		}
		if redirect == "" {
			return nil, nil
		}
		id = redirect
	}
	return nil, errors.New("Too many Yadis redirects")
}

func (q Query) yadisProcess(r *http.Response) (body io.Reader, redirect string, err error) {
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
		q.logf(`fetching xrds found in html "%s"`, url_)
		return nil, url_, nil
	}

	// If the response contain an X-XRDS-Location header
	xrds_location := r.Header.Get("X-Xrds-Location")
	if len(xrds_location) > 0 {
		q.logf(`fetching xrds found in http header "%s"`, xrds_location)
		return nil, xrds_location, nil
	}

	q.logf("Yadis fails out, nothing found. status=%#v", r.StatusCode)
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
