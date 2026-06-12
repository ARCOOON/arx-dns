package firewall

import "errors"

var errUnknownBlockAction = errors.New("unknown block-action; use NXDOMAIN or ZEROIP")
