// Copyright 2010 Florian Duraffourg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openid

import (
	"encoding/xml"
	"io"
	"strings"
)

type xrdsIdentifier struct {
	XMLName xml.Name "Service"
	Type    []string
	URI     string
	LocalID string
}
type xrd struct {
	XMLName xml.Name "XRD"
	Service xrdsIdentifier
}
type xrds struct {
	XMLName xml.Name "XRDS"
	XRD     xrd
}

// Parse a XRDS document provided through a io.Reader
// Return the OP EndPoint and, if found, the Claimed Identifier
func ParseXRDS(r io.Reader) (string, string) {
	xrds := new(xrds)
	err := xml.NewDecoder(r).Decode(xrds)
	if err != nil {
		//fmt.Printf(err.String())
		return "", ""
	}
	XRDSI := xrds.XRD.Service

	XRDSI.URI = strings.TrimSpace(XRDSI.URI)
	XRDSI.LocalID = strings.TrimSpace(XRDSI.LocalID)

	//fmt.Printf("%v\n", XRDSI)

	if stringTableContains(XRDSI.Type, "http://specs.openid.net/auth/2.0/server") {
		//fmt.Printf("OP Identifier Element found\n")
		return XRDSI.URI, ""
	} else if stringTableContains(XRDSI.Type, "http://specs.openid.net/auth/2.0/signon") {
		//fmt.Printf("Claimed Identifier Element found\n")
		return XRDSI.URI, XRDSI.LocalID
	}
	return "", ""
}

func stringTableContains(t []string, s string) bool {
	for _, v := range t {
		if v == s {
			return true
		}
	}
	return false
}
