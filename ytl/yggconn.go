// Ytl by DomesticMoth
//
// To the extent possible under law, the person who associated CC0 with
// ytl has waived all copyright and related or neighboring rights
// to ytl.
//
// You should have received a copy of the CC0 legalcode along with this
// work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
package ytl

import (
	"io"
	"net"
	"time"
	"bytes"
	"crypto/ed25519"
	"github.com/DomesticMoth/ytl/ytl/static"
)


func internalParceMetaPackage(conn net.Conn) (
	err error,
	version *static.ProtoVersion,
	pkey ed25519.PublicKey,
	buf []byte,
) {
	buf = make([]byte, len(static.META_HEADER())+2+ed25519.PublicKeySize)
	_, err = io.ReadFull(conn, buf);
	if err != nil { return }
	if bytes.Compare(static.META_HEADER(), buf[:len(static.META_HEADER())]) != 0 {
		// Unknown proto
		err = static.UnknownProtoError{}
		return
	}
	version = &static.ProtoVersion{
		buf[len(static.META_HEADER())],
		buf[len(static.META_HEADER())+1],
	}
	target_version := static.PROTO_VERSION()
	if version.Major != target_version.Major || version.Minor != target_version.Minor {
		// Unknown proto version
		err = static.UnknownProtoVersionError{
			Expected: static.PROTO_VERSION(),
			Received: *version,
		}
		return
	}
	key_raw := buf[len(buf)-ed25519.PublicKeySize:]
	pkey = make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pkey, key_raw)
	return
}

func parceMetaPackage(conn net.Conn, timeout time.Duration) (
	err error,
	version *static.ProtoVersion,
	pkey ed25519.PublicKey,
	buf []byte,
) {
	type result struct {
		err error
		version *static.ProtoVersion
		pkey ed25519.PublicKey
		buf []byte
	}
	ret := make(chan result, 1)
	go func(){
		err, version, pkey, buf := internalParceMetaPackage(conn)
		ret <- result{err, version, pkey, buf}
	}()
    select {
    	case <-time.After(timeout):
    		conn.Close()
    		err = static.ConnTimeoutError{}
        	return
    	case ret := <-ret:
			err = ret.err
			version = ret.version
			pkey = ret.pkey
			buf = ret.buf
        	return
	}
	return
}

type YggConn struct{
	innerConn net.Conn
	transport_key ed25519.PublicKey
	allowList *static.AllowList
	secureTranport bool
	extraReadBuffChn chan []byte
	err error
	dm *DeduplicationManager
	closefn func()
	pVersion chan *static.ProtoVersion
	otherPublicKey chan ed25519.PublicKey
	isClosed chan bool
}

func ConnToYggConn(conn net.Conn, transport_key ed25519.PublicKey, allow *static.AllowList, secureTranport bool, dm *DeduplicationManager) *YggConn {
	if conn == nil {return nil}
	isClosed := make(chan bool, 1)
	isClosed <- false
	ret := YggConn{
		conn,
		transport_key,
		allow,
		secureTranport,
		make(chan []byte, 1),
		nil,
		dm,
		func(){},
		make(chan *static.ProtoVersion, 1),
		make(chan ed25519.PublicKey, 1),
		isClosed,
	}
	go ret.middleware()
	return &ret
}

func (y * YggConn) setErr(err error) {
	if y.err == nil {
		y.err = err
	}
	y.Close()
}

func (y * YggConn) middleware() {
	onerror := func(e error) {
		y.setErr(e)
		y.extraReadBuffChn <- nil
	}
	err, version, pkey, buf := parceMetaPackage(y.innerConn, time.Minute)
	y.pVersion <- version
	y.otherPublicKey <- pkey
	if len(buf) == 0 { buf = nil }
	if err != nil  {
		onerror(err)
		return
	}
	// Check if node keq equal transport key
	if y.transport_key != nil {
		if bytes.Compare(y.transport_key, pkey) != 0 {
			// Invalid transport key
			onerror(static.TransportSecurityCheckError{
				Expected: y.transport_key,
				Received: pkey,
			})
			return
		}
	}
	if y.allowList != nil {
		if !y.allowList.IsAllow(pkey) {
			// TODO Write more human readable error text
			onerror(static.IvalidPeerPublicKey{
				"Key received from the peer is not in the allow list",
			})
			return
		}
	}
	if y.dm != nil {
		closefunc := y.dm.Check(pkey, y.secureTranport, func(){
			y.setErr(static.ConnClosedByDeduplicatorError{})
		})
		if closefunc == nil {
			onerror(static.ConnClosedByDeduplicatorError{})
			return
		}
		y.closefn = closefunc
	}
	// 
	y.extraReadBuffChn <- buf
}

func (y * YggConn) GetVer() (*static.ProtoVersion, error) {
	v := <- y.pVersion
	defer func(){y.pVersion <- v}()
	if v == nil { return nil, y.err }
	return v, nil
}

func (y * YggConn) GetPublicKey() (ed25519.PublicKey, error) {
	k := <- y.otherPublicKey
	defer func(){y.otherPublicKey <- k}()
	if k == nil { return nil, y.err }
	return k, nil
}

func (y * YggConn) Close() (err error) {
	closed := <- y.isClosed
	defer func(){y.isClosed <- closed}()
	closed = true
	if y.closefn != nil && !closed{
		y.closefn()
		y.closefn = func(){}
	}
	err = y.innerConn.Close()
	if y.err != nil { err = y.err }
	return err
}

func (y * YggConn) Read(b []byte) (n int, err error) {
	buf := <- y.extraReadBuffChn
	defer func(){ y.extraReadBuffChn <- buf }()
	if buf != nil {
		err = nil
		n = copy(b, buf)
		if n >= len(buf) {
			buf = nil
		}else{
			buf = buf[n:]
		}
		return
	}
	n, err = y.innerConn.Read(b)
	if y.err != nil { err = y.err }
	return
}

func (y * YggConn) Write(b []byte) (n int, err error) {
	n, err = y.innerConn.Write(b)
	if y.err != nil { err = y.err }
	return
}

func (y * YggConn) LocalAddr() net.Addr {
	return y.innerConn.LocalAddr()
}

func (y * YggConn) RemoteAddr() net.Addr {
	return y.innerConn.RemoteAddr()
}

func (y * YggConn) SetDeadline(t time.Time) (err error) {
	err = y.innerConn.SetDeadline(t)
	if y.err != nil { err = y.err }
	return
}

func (y * YggConn) SetReadDeadline(t time.Time) (err error) {
	err = y.innerConn.SetReadDeadline(t)
	if y.err != nil { err = y.err }
	return
}

func (y * YggConn) SetWriteDeadline(t time.Time) (err error) {
	err = y.innerConn.SetWriteDeadline(t)
	if y.err != nil { err = y.err }
	return
}

type YggListener struct {
	inner_listener net.Listener
	secure bool
	dm *DeduplicationManager
}

// Accept waits for and returns the next connection to the listener.
func (y * YggListener) Accept() (ygg YggConn, err error) {
	conn, err := y.inner_listener.Accept()
	if err != nil { return }
	yggr := ConnToYggConn(conn, nil, nil, y.secure, y.dm)
	ygg = *yggr
	return
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (y * YggListener) Close() error {
	return y.inner_listener.Close()
}

// Addr returns the listener's network address.
func (y * YggListener) Addr() net.Addr {
	return y.inner_listener.Addr()
}
