package dnssec

import (
	"crypto"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

const (
	// Algorithm is ECDSA Curve P-256 with SHA-256 (DNSSEC algorithm 13).
	Algorithm     = mdns.ECDSAP256SHA256
	algorithmBits = 256
)

// KeyType identifies the role of a DNSSEC key.
type KeyType string

const (
	KeyTypeKSK KeyType = "KSK"
	KeyTypeZSK KeyType = "ZSK"
)

// KeyMaterial holds a DNSKEY and its private signing material.
type KeyMaterial struct {
	KeyType   KeyType
	DNSKEY    *mdns.DNSKEY
	Private   crypto.PrivateKey
	CreatedAt time.Time
}

// GenerateKeyPair creates a new DNSSEC key of keyType for origin.
func GenerateKeyPair(origin string, keyType KeyType, ttl uint32) (*KeyMaterial, error) {
	origin = mdns.CanonicalName(origin)
	if origin == "" || origin == "." {
		return nil, fmt.Errorf("invalid zone origin %q", origin)
	}

	flags := uint16(mdns.ZONE)
	if keyType == KeyTypeKSK {
		flags |= mdns.SEP
	}

	dnskey := &mdns.DNSKEY{
		Hdr: mdns.RR_Header{
			Name:   origin,
			Rrtype: mdns.TypeDNSKEY,
			Class:  mdns.ClassINET,
			Ttl:    ttl,
		},
		Flags:     flags,
		Protocol:  3,
		Algorithm: Algorithm,
	}

	priv, err := dnskey.Generate(algorithmBits)
	if err != nil {
		return nil, fmt.Errorf("generate %s DNSKEY: %w", keyType, err)
	}

	return &KeyMaterial{
		KeyType:   keyType,
		DNSKEY:    dnskey,
		Private:   priv,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// EncodePrivateKeyPEM wraps the BIND private-key-format string in a PEM block.
func EncodePrivateKeyPEM(dnskey *mdns.DNSKEY, priv crypto.PrivateKey) (string, error) {
	if dnskey == nil || priv == nil {
		return "", fmt.Errorf("dnskey and private key are required")
	}
	body := dnskey.PrivateKeyString(priv)
	if body == "" {
		return "", fmt.Errorf("unsupported private key type")
	}
	block := &pem.Block{
		Type:  "DNSSEC PRIVATE KEY",
		Bytes: []byte(body),
	}
	return string(pem.EncodeToMemory(block)), nil
}

// EncodePublicKeyPEM stores the DNSKEY public record as a PEM block.
func EncodePublicKeyPEM(dnskey *mdns.DNSKEY) (string, error) {
	if dnskey == nil {
		return "", fmt.Errorf("dnskey is required")
	}
	block := &pem.Block{
		Type:  "DNSSEC PUBLIC KEY",
		Bytes: []byte(dnskey.String()),
	}
	return string(pem.EncodeToMemory(block)), nil
}

// LoadPrivateKey decodes a PEM-wrapped BIND private key for dnskey.
func LoadPrivateKey(dnskey *mdns.DNSKEY, pemText string) (crypto.PrivateKey, error) {
	if dnskey == nil {
		return nil, fmt.Errorf("dnskey is required")
	}
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemText)))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM private key")
	}
	priv, err := dnskey.NewPrivateKey(string(block.Bytes))
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return priv, nil
}

// LoadPublicDNSKEY decodes a PEM-wrapped DNSKEY public record string.
func LoadPublicDNSKEY(pemText string) (*mdns.DNSKEY, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemText)))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM public key")
	}
	rr, err := mdns.NewRR(strings.TrimSpace(string(block.Bytes)))
	if err != nil {
		return nil, fmt.Errorf("parse public DNSKEY: %w", err)
	}
	dnskey, ok := rr.(*mdns.DNSKEY)
	if !ok {
		return nil, fmt.Errorf("PEM block is not a DNSKEY record")
	}
	return dnskey, nil
}

// DSRecord builds a delegation signer record from the KSK.
func DSRecord(origin string, ksk *mdns.DNSKEY, digestType uint8) (*mdns.DS, error) {
	if ksk == nil {
		return nil, fmt.Errorf("ksk is required")
	}
	ds := ksk.ToDS(digestType)
	if ds == nil {
		return nil, fmt.Errorf("unsupported digest type %d", digestType)
	}
	ds.Hdr.Name = mdns.CanonicalName(origin)
	return ds, nil
}

// FormatDS returns a registrar-friendly DS record line.
func FormatDS(origin string, ds *mdns.DS) string {
	if ds == nil {
		return ""
	}
	apex := strings.TrimSuffix(mdns.CanonicalName(origin), ".")
	return fmt.Sprintf("%s %d %d %d %s",
		apex,
		ds.KeyTag,
		ds.Algorithm,
		ds.DigestType,
		strings.ToUpper(ds.Digest),
	)
}
