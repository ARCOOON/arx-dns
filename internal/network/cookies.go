package network

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"net/netip"
)

const serverCookieLen = 8

// CookieEngine generates and verifies RFC 7873 server cookies using HMAC-SHA256.
// The engine reuses an internal HMAC instance so the hot path avoids per-query allocations.
type CookieEngine struct {
	mac    hash.Hash
	sumBuf [sha256.Size]byte
}

// NewCookieEngine builds a cookie engine from a 32-byte server secret.
func NewCookieEngine(secret []byte) *CookieEngine {
	return &CookieEngine{
		mac: hmac.New(sha256.New, secret),
	}
}

// ServerCookie writes an 8-byte server cookie into dst for the given client address
// and 8-byte client cookie. dst must have length at least serverCookieLen.
func (e *CookieEngine) ServerCookie(client netip.Addr, clientCookie [8]byte, dst []byte) {
	if e == nil || len(dst) < serverCookieLen {
		return
	}

	e.mac.Reset()
	if client.Is4() {
		var ip [4]byte
		copy(ip[:], client.AsSlice())
		e.mac.Write(ip[:])
	} else {
		var ip [16]byte
		copy(ip[:], client.AsSlice())
		e.mac.Write(ip[:])
	}
	e.mac.Write(clientCookie[:])

	sum := e.mac.Sum(e.sumBuf[:0])
	copy(dst, sum[:serverCookieLen])
}

// Verify reports whether serverCookie matches the HMAC for client and clientCookie.
func (e *CookieEngine) Verify(client netip.Addr, clientCookie [8]byte, serverCookie []byte) bool {
	if e == nil || len(serverCookie) != serverCookieLen {
		return false
	}

	var expected [serverCookieLen]byte
	e.ServerCookie(client, clientCookie, expected[:])
	return hmac.Equal(serverCookie, expected[:])
}
