// Copyright 2022 DomesticMoth
//
// This file is part of Ytl.
//
// Ytl is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// Ytl is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

package ytl

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"
	"github.com/Yggdrasil-Unofficial/ytl/debugstuff"
	"github.com/Yggdrasil-Unofficial/ytl/static"
	"github.com/Yggdrasil-Unofficial/ytl/transports"
	"net"
	"net/url"
	"testing"
)

func TestKeyFromOptionalKey(t *testing.T) {
	for _, opt := range []ed25519.PrivateKey{
		nil,
		make(ed25519.PrivateKey, ed25519.PrivateKeySize),
	} {
		if KeyFromOptionalKey(opt) == nil {
			t.Fatalf("Key must not be nil")
		}
	}
}

func TestConnManagerListening(t *testing.T) {
	manager := NewConnManager(context.Background(), nil, nil, nil, nil)
	manager.transports["b"] = debugstuff.MockTransport{"b", 0}
	uri, _ := url.Parse("a://b")
	_, err := manager.Listen(*uri)
	if err == nil {
		t.Fatalf("Must raise error")
	}
	uri, _ = url.Parse("tcp://8.8.8.8:42")
	_, err = manager.Listen(*uri)
	if err == nil {
		t.Fatalf("Must raise error")
	}
	uri, _ = url.Parse("b://a")
	_, err = manager.Listen(*uri)
	if err != nil {
		t.Fatalf("Mustnt raise error")
	}
}

func TestConnManagerDefultTransports(t *testing.T) {
	ctx := context.Background()
	a := NewConnManager(ctx, nil, nil, nil, nil)
	b := NewConnManagerWithTransports(ctx, nil, nil, nil, nil, transports.DEFAULT_TRANSPORTS())
	if len(a.transports) != len(b.transports) {
		t.Fatalf("Must be same maps")
	}
	for key := range a.transports {
		if _, ok := b.transports[key]; !ok {
			t.Fatalf("Must be same maps")
		}
	}
	for key := range b.transports {
		if _, ok := a.transports[key]; !ok {
			t.Fatalf("Must be same maps")
		}
	}
}

func TestConnManagerTransportSelection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestConnManagerTransportSelection in short mode.")
	}
	transportsObjects := []static.Transport{
		debugstuff.MockTransport{Scheme: "a", SecureLvl: 0},
		debugstuff.MockTransport{Scheme: "b", SecureLvl: 0},
		debugstuff.MockTransport{Scheme: "c", SecureLvl: 0},
	}
	type Case struct {
		Scheme string
		Exist  bool
	}
	cases := []Case{
		{"a", true},
		{"b", true},
		{"c", true},
		{"d", false},
	}
	pkey := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	manager := NewConnManagerWithTransports(
		context.Background(),
		pkey,
		nil,
		nil,
		nil,
		transportsObjects,
	)
	for _, c := range cases {
		uri, _ := url.Parse(fmt.Sprintf("%s://host:123", c.Scheme))
		res, err := manager.Connect(*uri)
		if c.Exist {
			if err != nil {
				t.Errorf("Unexpected error: %s", err)
				continue
			}
			info := debugstuff.ReadMockTransportInfoAfterHeader(res)
			correct := debugstuff.FormatMockTransportInfo(c.Scheme, *uri, nil, false, pkey)
			if info != correct {
				t.Errorf("Wrong info returned from connection: %s %s", info, correct)
			}
		} else if err == nil {
			t.Errorf("Connecting to an unsupported transport should cause an error")
		}
	}
}

// Testing that connection manager creating random key
// for each connection if nil key was passed to constructor.
func TestConnManagerKeyMaterialisation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestConnManagerKeyMaterialisation in short mode.")
	}
	transports := []static.Transport{
		debugstuff.MockTransport{Scheme: "a", SecureLvl: 0},
	}
	uri, _ := url.Parse("a://host:123")
	for _, key := range []ed25519.PrivateKey{
		nil,
		make(ed25519.PrivateKey, ed25519.PrivateKeySize),
	} {
		manager := NewConnManagerWithTransports(
			context.Background(),
			key,
			nil,
			nil,
			nil,
			transports,
		)
		res, err := manager.Connect(*uri)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
			continue
		}
		info := debugstuff.ReadMockTransportInfoAfterHeader(res)
		incorrect := debugstuff.FormatMockTransportInfo("a", *uri, nil, false, nil)
		if info == incorrect {
			t.Errorf("Wrong info returned from connection: %s", info)
			continue
		}
		if key != nil {
			correct := debugstuff.FormatMockTransportInfo("a", *uri, nil, false, key)
			if info != correct {
				t.Errorf("Wrong info returned from connection: %s %s", info, correct)
			}
		}
	}
}

// Testing that all connections are acceptable
// if there is no AllowList passed
func TestConnManagerNoAllowList(t *testing.T) {
	transports := []static.Transport{
		debugstuff.MockTransport{Scheme: "a", SecureLvl: 0},
	}
	pkey := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	for i := 0; i < 1000; i++ {
		manager := NewConnManagerWithTransports(
			context.Background(),
			pkey,
			nil,
			nil,
			nil,
			transports,
		)
		transportKey := KeyFromOptionalKey(nil)
		uri, _ := url.Parse(
			fmt.Sprintf("a://host:123?mock_transport_key=%s", hex.EncodeToString(transportKey)),
		)
		_, err := manager.Connect(*uri)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}
	}
}

func publicKeyFromOptionalKey(key ed25519.PublicKey) ed25519.PublicKey {
	if key != nil {
		return key
	}
	spub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return spub
}

// Testing that only connections with
// nodes from AllowList are acceptable
func TestConnManagerAllowList(t *testing.T) {
	pkey := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	transports := []static.Transport{
		debugstuff.MockTransport{Scheme: "a", SecureLvl: 0},
	}
	allow1 := make(ed25519.PublicKey, ed25519.PublicKeySize)
	allow2 := make(ed25519.PublicKey, ed25519.PublicKeySize)
	allow1[0] = 1
	allow2[0] = 2
	allowList := static.AllowList{allow1, allow2}
	testkey := func(key ed25519.PublicKey) (net.Conn, error) {
		manager := NewConnManagerWithTransports(
			context.Background(),
			pkey,
			nil,
			nil,
			&allowList,
			transports,
		)
		uri, _ := url.Parse(
			fmt.Sprintf("a://host:123?mock_transport_key=%s", hex.EncodeToString(key)),
		)
		return manager.Connect(*uri)
	}
	for i := 0; i < 100; i++ {
		transportKey := publicKeyFromOptionalKey(nil)
		if bytes.Compare(transportKey, allow1) == 0 || bytes.Compare(transportKey, allow2) == 0 {
			continue
		}
		_, err := testkey(transportKey)
		if err == nil {
			t.Errorf("Using a key that is not in the AllowList should result in an error")
		}
	}
	for _, transportKey := range []ed25519.PublicKey{allow1, allow2} {
		_, err := testkey(transportKey)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
			continue
		}
	}
}

// Testing that uri "key" key ignoring AllowList
func TestConnManagerIgnoreAllowList(t *testing.T) {
	pkey := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	transports := []static.Transport{
		debugstuff.MockTransport{Scheme: "a", SecureLvl: 0},
	}
	allow := make(ed25519.PublicKey, ed25519.PublicKeySize)
	allowList := static.AllowList{allow}
	testkey := func(key ed25519.PublicKey) (net.Conn, error) {
		manager := NewConnManagerWithTransports(
			context.Background(),
			pkey,
			nil,
			nil,
			&allowList,
			transports,
		)
		uri, _ := url.Parse(
			fmt.Sprintf(
				"a://host:123?mock_transport_key=%s&key=%s",
				hex.EncodeToString(key),
				hex.EncodeToString(key),
			),
		)
		return manager.Connect(*uri)
	}
	for i := 0; i < 100; i++ {
		transportKey := publicKeyFromOptionalKey(nil)
		if i == 0 {
			transportKey = allow
		}
		_, err := testkey(transportKey)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}
	}
}

func TestConnManagerConnectTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestConnManagerConnectTimeout in short mode.")
	}
	transports := []static.Transport{
		debugstuff.MockTransport{Scheme: "a", SecureLvl: 0},
	}
	durationText := "1s"
	duration, err := time.ParseDuration(durationText)
	uri, _ := url.Parse("a://host")
	manager := NewConnManagerWithTransports(context.Background(), nil, nil, nil, nil, transports)
	_, err = manager.ConnectTimeout(*uri, duration)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	uri, _ = url.Parse("a://host?mock_delay_conn=2s")
	_, err = manager.ConnectTimeout(*uri, duration)
	if err == nil {
		t.Errorf("Must raise timeout error")
	}
}
