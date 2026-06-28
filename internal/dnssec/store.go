package dnssec

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

// Status describes DNSSEC signing state for a zone.
type Status struct {
	Enabled   bool      `json:"enabled"`
	Zone      string    `json:"zone"`
	View      string    `json:"view"`
	Algorithm uint8     `json:"algorithm"`
	KSKTag    uint16    `json:"ksk_tag,omitempty"`
	ZSKTag    uint16    `json:"zsk_tag,omitempty"`
	DS        string    `json:"ds,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

// Store persists DNSSEC keys in main.db.
type Store struct {
	db *sql.DB
}

// NewStore creates a DNSSEC key store backed by db.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// IsEnabled reports whether both KSK and ZSK exist for zone/view.
func (s *Store) IsEnabled(zone, view string) (bool, error) {
	if s == nil || s.db == nil {
		return false, nil
	}
	zone = normalizeZone(zone)
	view = normalizeView(view)

	const query = `
SELECT COUNT(*) FROM dnssec_keys
WHERE zone = ? AND view = ? AND key_type IN ('KSK', 'ZSK');
`
	var count int
	if err := s.db.QueryRow(query, zone, view).Scan(&count); err != nil {
		return false, fmt.Errorf("query dnssec keys: %w", err)
	}
	return count >= 2, nil
}

// SaveKey persists a generated key pair.
func (s *Store) SaveKey(zone, view string, material *KeyMaterial) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("dnssec store is nil")
	}
	if material == nil || material.DNSKEY == nil || material.Private == nil {
		return fmt.Errorf("key material is incomplete")
	}

	zone = normalizeZone(zone)
	view = normalizeView(view)

	privPEM, err := EncodePrivateKeyPEM(material.DNSKEY, material.Private)
	if err != nil {
		return err
	}
	pubPEM, err := EncodePublicKeyPEM(material.DNSKEY)
	if err != nil {
		return err
	}

	const query = `
INSERT INTO dnssec_keys (zone, view, key_type, algorithm, private_key_pem, public_key_pem, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(zone, view, key_type) DO UPDATE SET
	algorithm = excluded.algorithm,
	private_key_pem = excluded.private_key_pem,
	public_key_pem = excluded.public_key_pem,
	created_at = excluded.created_at;
`
	_, err = s.db.Exec(
		query,
		zone,
		view,
		string(material.KeyType),
		material.DNSKEY.Algorithm,
		privPEM,
		pubPEM,
		material.CreatedAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("save dnssec key: %w", err)
	}
	return nil
}

// LoadKeys returns KSK and ZSK material for zone/view.
func (s *Store) LoadKeys(zone, view string) (ksk, zsk *KeyMaterial, err error) {
	if s == nil || s.db == nil {
		return nil, nil, fmt.Errorf("dnssec store is nil")
	}
	zone = normalizeZone(zone)
	view = normalizeView(view)

	const query = `
SELECT key_type, algorithm, private_key_pem, public_key_pem, created_at
FROM dnssec_keys
WHERE zone = ? AND view = ?;
`
	rows, err := s.db.Query(query, zone, view)
	if err != nil {
		return nil, nil, fmt.Errorf("query dnssec keys: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			keyType   string
			algorithm uint8
			privPEM   string
			pubPEM    string
			created   string
		)
		if err := rows.Scan(&keyType, &algorithm, &privPEM, &pubPEM, &created); err != nil {
			return nil, nil, fmt.Errorf("scan dnssec key: %w", err)
		}

		dnskey, err := LoadPublicDNSKEY(pubPEM)
		if err != nil {
			return nil, nil, err
		}
		dnskey.Hdr.Name = zone
		dnskey.Algorithm = algorithm

		priv, err := LoadPrivateKey(dnskey, privPEM)
		if err != nil {
			return nil, nil, err
		}

		createdAt, _ := time.Parse(time.RFC3339, created)
		material := &KeyMaterial{
			KeyType:   KeyType(keyType),
			DNSKEY:    dnskey,
			Private:   priv,
			CreatedAt: createdAt,
		}

		switch KeyType(keyType) {
		case KeyTypeKSK:
			ksk = material
		case KeyTypeZSK:
			zsk = material
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate dnssec keys: %w", err)
	}
	if ksk == nil || zsk == nil {
		return ksk, zsk, fmt.Errorf("missing KSK or ZSK for zone %s view %s", zone, view)
	}
	return ksk, zsk, nil
}

// Status returns DNSSEC signing status and DS record text for zone/view.
func (s *Store) Status(zone, view string) (Status, error) {
	zone = normalizeZone(zone)
	view = normalizeView(view)

	enabled, err := s.IsEnabled(zone, view)
	if err != nil {
		return Status{}, err
	}

	status := Status{
		Enabled: enabled,
		Zone:    zone,
		View:    view,
	}
	if !enabled {
		return status, nil
	}

	ksk, zsk, err := s.LoadKeys(zone, view)
	if err != nil {
		return Status{}, err
	}

	status.Algorithm = ksk.DNSKEY.Algorithm
	status.KSKTag = ksk.DNSKEY.KeyTag()
	status.ZSKTag = zsk.DNSKEY.KeyTag()
	status.CreatedAt = ksk.CreatedAt

	ds, err := DSRecord(zone, ksk.DNSKEY, mdns.SHA256)
	if err != nil {
		return Status{}, err
	}
	status.DS = FormatDS(zone, ds)
	return status, nil
}

// EnsureKeys generates and stores KSK/ZSK when missing.
func (s *Store) EnsureKeys(zone, view string, ttl uint32) error {
	enabled, err := s.IsEnabled(zone, view)
	if err != nil {
		return err
	}
	if enabled {
		return nil
	}

	zone = normalizeZone(zone)
	for _, keyType := range []KeyType{KeyTypeKSK, KeyTypeZSK} {
		material, err := GenerateKeyPair(zone, keyType, ttl)
		if err != nil {
			return err
		}
		if err := s.SaveKey(zone, view, material); err != nil {
			return err
		}
	}
	return nil
}

// DeleteKeys removes all DNSSEC keys for zone/view.
func (s *Store) DeleteKeys(zone, view string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("dnssec store is nil")
	}
	zone = normalizeZone(zone)
	view = normalizeView(view)
	_, err := s.db.Exec(`DELETE FROM dnssec_keys WHERE zone = ? AND view = ?;`, zone, view)
	if err != nil {
		return fmt.Errorf("delete dnssec keys: %w", err)
	}
	return nil
}

func normalizeZone(zone string) string {
	zone = strings.TrimSpace(strings.ToLower(zone))
	if zone == "" {
		return "."
	}
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}
	return zone
}

func normalizeView(view string) string {
	view = strings.TrimSpace(strings.ToLower(view))
	if view == "" {
		return "public"
	}
	return view
}
