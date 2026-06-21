package acl

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	ActionAllow = "allow"
	ActionBlock = "block"
)

// Rule is one client subnet policy stored in main.db.
type Rule struct {
	ID          int64  `json:"id"`
	Subnet      string `json:"subnet"`
	Description string `json:"description,omitempty"`
	Action      string `json:"action"`
}

var (
	// ErrRuleNotFound is returned when an ACL rule ID does not exist.
	ErrRuleNotFound = errors.New("acl rule not found")
	// ErrRuleAlreadyExists is returned when the subnet is already registered.
	ErrRuleAlreadyExists = errors.New("acl rule already exists")
	// ErrInvalidSubnet is returned when a subnet is empty or not a valid IP/CIDR.
	ErrInvalidSubnet = errors.New("invalid subnet")
	// ErrInvalidAction is returned when an action is not allow or block.
	ErrInvalidAction = errors.New("invalid action")
)

// NormalizeAction validates and canonicalizes an ACL action.
func NormalizeAction(raw string) (string, error) {
	action := strings.ToLower(strings.TrimSpace(raw))
	if action == "" {
		return ActionAllow, nil
	}
	switch action {
	case ActionAllow, ActionBlock:
		return action, nil
	default:
		return "", ErrInvalidAction
	}
}

// NormalizeSubnet validates and canonicalizes an IP address or CIDR prefix.
func NormalizeSubnet(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ErrInvalidSubnet
	}

	if ip := net.ParseIP(raw); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String() + "/32", nil
		}
		return ip.String() + "/128", nil
	}

	_, network, err := net.ParseCIDR(raw)
	if err != nil {
		return "", ErrInvalidSubnet
	}

	ones, _ := network.Mask.Size()
	if ip4 := network.IP.To4(); ip4 != nil {
		return fmt.Sprintf("%s/%d", ip4.String(), ones), nil
	}
	return fmt.Sprintf("%s/%d", network.IP.String(), ones), nil
}

// InsertRule registers a new client subnet policy.
func InsertRule(db *sql.DB, subnet, description, action string) (Rule, error) {
	if db == nil {
		return Rule{}, fmt.Errorf("database handle is nil")
	}

	normalized, err := NormalizeSubnet(subnet)
	if err != nil {
		return Rule{}, err
	}

	normalizedAction, err := NormalizeAction(action)
	if err != nil {
		return Rule{}, err
	}

	description = strings.TrimSpace(description)

	const query = `
INSERT INTO acl_rules (subnet, description, action)
VALUES (?, ?, ?)
RETURNING id, subnet, description, action;
`

	var rule Rule
	var descriptionCol sql.NullString
	if err := db.QueryRow(query, normalized, nullableDescription(description), normalizedAction).Scan(
		&rule.ID,
		&rule.Subnet,
		&descriptionCol,
		&rule.Action,
	); err != nil {
		if isUniqueConstraintError(err) {
			return Rule{}, ErrRuleAlreadyExists
		}
		return Rule{}, fmt.Errorf("insert acl rule: %w", err)
	}
	if descriptionCol.Valid {
		rule.Description = strings.TrimSpace(descriptionCol.String)
	}

	return rule, nil
}

// UpdateRule modifies an existing ACL rule.
func UpdateRule(db *sql.DB, id int64, subnet, description, action string) (Rule, error) {
	if db == nil {
		return Rule{}, fmt.Errorf("database handle is nil")
	}
	if id <= 0 {
		return Rule{}, ErrRuleNotFound
	}

	normalized, err := NormalizeSubnet(subnet)
	if err != nil {
		return Rule{}, err
	}

	normalizedAction, err := NormalizeAction(action)
	if err != nil {
		return Rule{}, err
	}

	description = strings.TrimSpace(description)

	const query = `
UPDATE acl_rules
SET subnet = ?, description = ?, action = ?
WHERE id = ?
RETURNING id, subnet, description, action;
`

	var rule Rule
	var descriptionCol sql.NullString
	if err := db.QueryRow(query, normalized, nullableDescription(description), normalizedAction, id).Scan(
		&rule.ID,
		&rule.Subnet,
		&descriptionCol,
		&rule.Action,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Rule{}, ErrRuleNotFound
		}
		if isUniqueConstraintError(err) {
			return Rule{}, ErrRuleAlreadyExists
		}
		return Rule{}, fmt.Errorf("update acl rule: %w", err)
	}
	if descriptionCol.Valid {
		rule.Description = strings.TrimSpace(descriptionCol.String)
	}

	return rule, nil
}

// ListRules returns all configured ACL rules ordered by ID.
func ListRules(db *sql.DB) ([]Rule, error) {
	if db == nil {
		return nil, fmt.Errorf("database handle is nil")
	}

	const query = `
SELECT id, subnet, description, action
FROM acl_rules
ORDER BY id ASC;
`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("list acl rules: %w", err)
	}
	defer rows.Close()

	rules := make([]Rule, 0)
	for rows.Next() {
		rule, err := scanRule(rows.Scan)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate acl rules: %w", err)
	}

	return rules, nil
}

// DeleteRule removes an ACL rule by ID.
func DeleteRule(db *sql.DB, id int64) error {
	if db == nil {
		return fmt.Errorf("database handle is nil")
	}
	if id <= 0 {
		return ErrRuleNotFound
	}

	const query = `DELETE FROM acl_rules WHERE id = ?;`

	result, err := db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("delete acl rule: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete acl rule rows affected: %w", err)
	}
	if rows == 0 {
		return ErrRuleNotFound
	}

	return nil
}

func scanRule(scan func(dest ...any) error) (Rule, error) {
	var rule Rule
	var description sql.NullString
	if err := scan(&rule.ID, &rule.Subnet, &description, &rule.Action); err != nil {
		return Rule{}, fmt.Errorf("scan acl rule: %w", err)
	}
	if description.Valid {
		rule.Description = strings.TrimSpace(description.String)
	}
	if rule.Action == "" {
		rule.Action = ActionAllow
	}
	return rule, nil
}

func nullableDescription(description string) any {
	if description == "" {
		return nil
	}
	return description
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique constraint") || strings.Contains(message, "constraint failed")
}
