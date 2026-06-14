package storage

import "errors"

var (
	// ErrUpdateNXRRSET indicates a prerequisite or update expected an RRset that does not exist.
	ErrUpdateNXRRSET = errors.New("rrset does not exist")
	// ErrUpdateYXRRSET indicates a prerequisite expected an RRset to be absent but it exists.
	ErrUpdateYXRRSET = errors.New("rrset already exists")
	// ErrUpdateNXDOMAIN indicates a prerequisite or update expected a name that does not exist.
	ErrUpdateNXDOMAIN = errors.New("name does not exist")
	// ErrUpdateYXDOMAIN indicates a prerequisite expected a name to be unused but it exists.
	ErrUpdateYXDOMAIN = errors.New("name already exists")
	// ErrUpdateNotZone indicates a name is not within the updated zone.
	ErrUpdateNotZone = errors.New("name not in zone")
	// ErrUpdateRefused indicates the update is not permitted (e.g. protected record).
	ErrUpdateRefused = errors.New("update refused")
)
