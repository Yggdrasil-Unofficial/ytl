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
	"crypto/ed25519"
	"encoding/hex"
	"github.com/Yggdrasil-Unofficial/ytl/debugstuff"
	"github.com/Yggdrasil-Unofficial/ytl/static"
	"io"
	"os"
	"net"
	"net/url"
	"testing"
	"time"
	"context"
	"go.uber.org/goleak"
)

func TestParceMetaPackageWrongProto(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		a.Write([]byte{'a', 't', 'a', 'm', 0, 4})
		a.Write(make(ed25519.PublicKey, ed25519.PublicKeySize))
	}()
	err, _, _, _ := internalParseMetaPackage(b)
	if err == nil {
		t.Fatalf("Must raise UnknownProtoError")
	}
}

type CaseTestParceMetaPackage struct {
	conn    net.Conn
	err     error
	version *static.ProtoVersion
	pkey    ed25519.PublicKey
	buf     []byte
}

func TestParceMetaPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestParceMetaPackage in short mode.")
	}
	v := static.PROTO_VERSION()
	v2 := static.ProtoVersion{Major: 1, Minor: 5}
	cases := []CaseTestParceMetaPackage{
		{
			debugstuff.MockConn(),
			nil,
			&v,
			debugstuff.MockPubKey(),
			debugstuff.MockConnContent()[:38],
		},
		{
			debugstuff.MockWrongVerConn(),
			static.UnknownProtoVersionError{
				Expected: static.PROTO_VERSION(),
				Received: v2,
			},
			&v2,
			nil,
			debugstuff.MockConnWrongVerContent()[:38],
		},
		{
			debugstuff.MockTooShortConn(),
			static.ConnTimeoutError{},
			nil,
			nil,
			nil,
		},
	}
	for _, cse := range cases {
		err, version, pkey, buf := parseMetaPackage(cse.conn, time.Minute/2)
		if err != cse.err {
			t.Fatalf("Wrong err %s %s", err, cse.err)
		}
		if version != nil && cse.version != nil {
			if version.Major != cse.version.Major || version.Minor != cse.version.Minor {
				t.Fatalf("Wrong version %s %s", version, cse.version)
			}
		} else if version != cse.version {
			t.Fatalf("Wrong version %s %s", version, cse.version)
		}
		if bytes.Compare(pkey, cse.pkey) != 0 {
			t.Fatalf(
				"Wrong PublicKey %s %s",
				hex.EncodeToString(pkey),
				hex.EncodeToString(cse.pkey),
			)
		}
		if bytes.Compare(buf, cse.buf) != 0 {
			t.Fatalf(
				"Wrong buf %s %s",
				hex.EncodeToString(buf),
				hex.EncodeToString(cse.buf),
			)
		}
	}
}

func TestYggConnCorrectReading(t *testing.T) {
	for i := 0; i < 2; i++ {
		strictMode := false
		if i > 0 {
			strictMode = true
		}
		for secure := 0; secure < 2; secure++ {
			data := debugstuff.MockConnContent()
			a := debugstuff.MockConn()
			dm := NewDeduplicationManager(strictMode, nil)
			yggcon := ConnToYggConn(
				a,
				debugstuff.MockPubKey(),
				nil,
				uint(secure),
				dm,
			)
			defer yggcon.Close()
			buf := make([]byte, len(data))
			n, err := io.ReadFull(yggcon, buf)
			if err != nil {
				t.Errorf("Error while reading from yggcon '%s'", err)
				t.Errorf("Readed only %d bytes from %d", n, len(data))
			}
			buf = buf[:n]
			if bytes.Compare(data, buf) != 0 {
				t.Errorf("Readed data is not eq to writed data")
			}
			target_version := static.PROTO_VERSION()
			version, err := yggcon.GetVer()
			if err != nil {
				t.Errorf("Error while reading verdion %s", err)
			} else {
				if version.Major != target_version.Major || version.Minor != target_version.Minor {
					t.Errorf("Invalid version")
				}
			}
			key, err := yggcon.GetPublicKey()
			if err != nil {
				t.Errorf("Error while reading public key %s", err)
			} else {
				if bytes.Compare(key, debugstuff.MockPubKey()) != 0 {
					t.Errorf("Invalid key")
				}
			}
		}
	}
}

func yggConnTestCollision(
	t *testing.T,
	n1, n2 uint, // secure params for connections
	n int, // The number of the connection to be CLOSED
) {
	dm := NewDeduplicationManager(true, nil)
	if n == 0 {
		dm = nil
	}
	a := debugstuff.MockConn()
	b := debugstuff.MockConn()
	yggcon1 := ConnToYggConn(
		a,
		debugstuff.MockPubKey(),
		nil,
		n1,
		dm,
	)
	yggcon2 := ConnToYggConn(
		b,
		debugstuff.MockPubKey(),
		nil,
		n2,
		dm,
	)
	defer yggcon1.Close()
	defer yggcon2.Close()
	buf := make([]byte, len(debugstuff.MockConnContent())-1)
	var err1, err2 error
	if n == 0 {
		_, err1 = io.ReadFull(yggcon2, buf)
		_, err2 = io.ReadFull(yggcon1, buf)
		if err1 != nil || err2 != nil {
			t.Fatalf("Conn was closed: %s; %s;", err1, err2)
		}
		return
	}
	if n == 1 {
		_, err1 = io.ReadFull(yggcon2, buf)
		_, err2 = io.ReadFull(yggcon1, buf)
	} else {
		_, err1 = io.ReadFull(yggcon1, buf)
		_, err2 = io.ReadFull(yggcon2, buf)
	}
	if err1 != nil {
		t.Fatalf("Wrong conn was closed: %s", err1)
	}
	if err2 == nil {
		t.Fatalf("Connection was not closed")
	}
	switch err2.(type) {
	case static.ConnClosedByDeduplicatorError:
		// Ok
	default:
		t.Fatalf("Connection was not closed by deduplicator: %s", err2)
	}
}

/*func TestYggConnCollisionII(t *testing.T){
	// TODO Fix II Collision deduplication bug
	// Second connection should be closed, but the first is closed
	yggConnTestCollision(t, false, false, 2)
}*/

func TestYggConnCollisionIS(t *testing.T) {
	yggConnTestCollision(t, 0, 1, 1)
}

func TestYggConnCollisionSI(t *testing.T) {
	yggConnTestCollision(t, 1, 0, 2)
}

func TestYggConnCollisionSS(t *testing.T) {
	yggConnTestCollision(t, 1, 0, 2)
}

func TestYggConnNoCollisionII(t *testing.T) {
	yggConnTestCollision(t, 0, 0, 0)
}

func TestYggConnNoCollisionIS(t *testing.T) {
	yggConnTestCollision(t, 0, 1, 0)
}

func TestYggConnNoCollisionSI(t *testing.T) {
	yggConnTestCollision(t, 1, 0, 0)
}

func TestYggConnNoCollisionSS(t *testing.T) {
	yggConnTestCollision(t, 1, 0, 0)
}

func TestYggConnWrite(t *testing.T) {
	a, b := net.Pipe()
	b.Close()
	a.Close()
	isClosed := make(chan bool, 1)
	isClosed <- false
	yc := YggConn{
		a,
		nil,
		nil,
		0,
		make(chan []byte, 1),
		nil,
		nil,
		func() {},
		make(chan *static.ProtoVersion, 1),
		make(chan ed25519.PublicKey, 1),
		isClosed,
	}
	_, err := yc.Write([]byte{1, 2, 3})
	if err == nil {
		t.Fatalf("Must rase error")
	}
}

func TestYggConnGettersSetters(t *testing.T) {
	d := time.Now()
	//d, _ := time.Parse("1s")
	a, _ := net.Pipe()
	yc := ConnToYggConn(a, nil, nil, 0, nil)
	if yc.LocalAddr() != a.LocalAddr() {
		t.Errorf("Must be same")
	}
	if yc.RemoteAddr() != a.RemoteAddr() {
		t.Errorf("Must be same")
	}
	if yc.SetDeadline(d) != a.SetDeadline(d) {
		t.Errorf("Must be same")
	}
	if yc.SetReadDeadline(d) != a.SetReadDeadline(d) {
		t.Errorf("Must be same")
	}
	if yc.SetWriteDeadline(d) != a.SetWriteDeadline(d) {
		t.Errorf("Must be same")
	}
}

func TestConnToYggConnNilConn(t *testing.T) {
	yc := ConnToYggConn(nil, nil, nil, 0, nil)
	if yc != nil {
		t.Fatalf("Must be nill")
	}
}

func TestYggListenerOk(t *testing.T) {
	uri, _ := url.Parse("a://b")
	tr := debugstuff.MockTransport{"a", 0}
	ls, _ := tr.Listen(nil, *uri, nil)
	listener := YggListener{ls, nil, nil}
	_, err := listener.Accept()
	if err != nil {
		t.Fatalf("Unecpected error: %s", err)
	}
	if listener.Addr() != listener.inner_listener.Addr() {
		t.Fatalf("Must be same")
	}
	listener.Close()
}

func TestYggListenerErr(t *testing.T) {
	uri, _ := url.Parse("a://b?error=true")
	tr := debugstuff.MockTransport{"a", 0}
	ls, _ := tr.Listen(nil, *uri, nil)
	listener := YggListener{ls, nil, nil}
	_, err := listener.Accept()
	if err == nil {
		t.Fatalf("Must raise error")
	}
	listener.Close()
}

func TestYggConnLeak(t *testing.T) {
    if os.Getenv("LEAKSTESTS") == "TRUE" {
        defer goleak.VerifyNone(t)
    }
	count := 100000
	if testing.Short() {
		count = 100
	}
	ctx := context.Background()
	uri, _ := url.Parse("a://b")
	transport := debugstuff.MockTransport{"a", 0}
	dm := NewDeduplicationManager(true, nil)
	for i := 0; i < count; i++ {
		conn, _ := transport.Connect(ctx, *uri, nil, nil)
		yggcon := ConnToYggConn(conn.Conn, nil, nil, 0, dm)
		yggcon.GetPublicKey()
		conn.Conn.Close()
		yggcon.Write([]byte{})
	}
}

func TestYggDisplacementConnLeak(t *testing.T) {
    if os.Getenv("LEAKSTESTS") == "TRUE" {
        defer goleak.VerifyNone(t)
    }
	count := 100000
	if testing.Short() {
		count = 100
	}
	ctx := context.Background()
	uri, _ := url.Parse("a://b")
	transport := debugstuff.MockTransport{"a", 0}
	dm := NewDeduplicationManager(true, nil)
	var conn *static.ConnResult = nil
	var yggcon *YggConn = nil
	for i := 0; i < count; i++ {
		c, _ := transport.Connect(ctx, *uri, nil, nil)
		conn = &c
		y := ConnToYggConn(conn.Conn, nil, nil, uint(i+1), dm)
		yggcon = y
		_, err := yggcon.Read(make([]byte, 4))
		if err != nil {
			t.Fatalf("Unexcepted error: %s", err)
		}
	}
	if conn != nil {
		conn.Conn.Close()
	}
	if yggcon != nil {
		yggcon.Write([]byte{})
	}
}
