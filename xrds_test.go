// Copyright 2010 Florian Duraffourg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openid

import (
	"bytes"
	"testing"
)

// ParseXRDS Test

type ParseXRDSTest struct {
	in         string
	OPEndPoint string
	ClaimedId  string
}

var ParseXRDSTests = []ParseXRDSTest{
	ParseXRDSTest{
		`<?xml version="1.0" encoding="UTF-8"?><xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)"><XRD><Service xmlns="xri://$xrd*($v*2.0)">
<Type>http://specs.openid.net/auth/2.0/signon</Type>
  <URI>https://www.exampleprovider.com/endpoint/</URI>
  <LocalID>https://exampleuser.exampleprovider.com/</LocalID>
  </Service></XRD></xrds:XRDS>`,
		"https://www.exampleprovider.com/endpoint/",
		"https://exampleuser.exampleprovider.com/",
	},
	ParseXRDSTest{
		`<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
<XRD>
    <Service>
        <Type>http://specs.openid.net/auth/2.0/server</Type>
        <Type>http://openid.net/srv/ax/1.0</Type>
        <Type>http://openid.net/sreg/1.0</Type>
        <Type>http://openid.net/extensions/sreg/1.1</Type>
        <URI priority="20">http://openid.orange.fr/server/</URI>
    </Service>
</XRD>
</xrds:XRDS>`,
		"http://openid.orange.fr/server/",
		"",
	},
}

func TestParseXRDS(t *testing.T) {
	for _, xrds := range ParseXRDSTests {
		q := Query{}
		err := q.parseXRDS(bytes.NewBuffer([]byte(xrds.in)))
		if q.OPEndpointURL != xrds.OPEndPoint || q.ClaimedID != xrds.ClaimedId || err != nil {
			t.Errorf(`ParseXRDS(%s) = (%s, %s, "%s") want (%s, %s, nil).`, xrds.in, q.OPEndpointURL, q.ClaimedID, err.Error(), xrds.OPEndPoint, xrds.ClaimedId)
		}
	}
}
