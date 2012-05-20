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
	xrds := xrds{}
	err := xml.NewDecoder(r).Decode(&xrds)
	if err != nil {
		//fmt.Printf(err.String())
		return "", ""
	}
	xrdsi := xrds.XRD.Service

	xrdsi.URI = strings.TrimSpace(xrdsi.URI)
	xrdsi.LocalID = strings.TrimSpace(xrdsi.LocalID)

	//fmt.Printf("%v\n", xrdsi)

	if stringTableContains(xrdsi.Type, "http://specs.openid.net/auth/2.0/server") {
		//fmt.Printf("OP Identifier Element found\n")
		return xrdsi.URI, ""
	} else if stringTableContains(xrdsi.Type, "http://specs.openid.net/auth/2.0/signon") {
		//fmt.Printf("Claimed Identifier Element found\n")
		return xrdsi.URI, xrdsi.LocalID
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
