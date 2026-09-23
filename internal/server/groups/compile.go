package groups

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Compile turns a parsed rule into the query that selects the devices matching
// it. Literals are bound as placeholders and field names come from the fixed
// allowlist, so nothing an administrator types is ever concatenated into SQL.
func Compile(n Node, tenantID uuid.UUID, now time.Time) (string, []any, error) {
	// $1 is the tenant, referenced by the frame below. The clock is bound only
	// if a field needs it: Postgres cannot infer the type of a parameter the
	// query never mentions, so binding it unconditionally fails every rule
	// that does not use last_seen_days.
	c := &compiler{args: []any{tenantID}, now: now}
	where, err := c.compile(n)
	if err != nil {
		return "", nil, err
	}
	query := `
		SELECT d.id FROM devices d
		LEFT JOIN device_inventory i ON i.device_id = d.id
		WHERE d.tenant_id = $1 AND d.status = 'active' AND (` + where + `)`
	return query, c.args, nil
}

type compiler struct {
	args []any
	now  time.Time
	// clock is the placeholder holding now, empty until a field asks for it.
	clock string
}

// clockPlaceholder binds the evaluation time on first use.
func (c *compiler) clockPlaceholder() string {
	if c.clock == "" {
		c.clock = c.bind(c.now)
	}
	return c.clock
}

// bind adds a value and returns its placeholder.
func (c *compiler) bind(v any) string {
	c.args = append(c.args, v)
	return "$" + strconv.Itoa(len(c.args))
}

func (c *compiler) compile(n Node) (string, error) {
	switch t := n.(type) {
	case And:
		return c.binary(t.Left, t.Right, "AND")
	case Or:
		return c.binary(t.Left, t.Right, "OR")
	case Not:
		inner, err := c.compile(t.Operand)
		if err != nil {
			return "", err
		}
		// COALESCE so that NOT over a NULL comparison (a device with no
		// inventory, say) is false rather than NULL, which would otherwise
		// make NOT match nothing in a confusing way.
		return "(NOT COALESCE(" + inner + ", false))", nil
	case Compare:
		return c.compare(t)
	case HasSoftware:
		return c.hasSoftware(t)
	}
	return "", fmt.Errorf("groups: unknown node %T", n)
}

func (c *compiler) binary(left, right Node, op string) (string, error) {
	l, err := c.compile(left)
	if err != nil {
		return "", err
	}
	r, err := c.compile(right)
	if err != nil {
		return "", err
	}
	return "(" + l + " " + op + " " + r + ")", nil
}

func (c *compiler) compare(t Compare) (string, error) {
	def, ok := fields[t.Field]
	if !ok {
		return "", fmt.Errorf("groups: unknown field %q", t.Field)
	}
	sqlOp, ok := operators[t.Op]
	if !ok {
		return "", fmt.Errorf("groups: unknown operator %q", t.Op)
	}
	column := def.sql
	if strings.Contains(column, clockParam) {
		column = strings.ReplaceAll(column, clockParam, c.clockPlaceholder())
	}
	if def.kind == numberField {
		return "(" + column + " " + sqlOp + " " + c.bind(t.Number) + ")", nil
	}
	return "(" + column + " " + sqlOp + " " + c.bind(t.Text) + ")", nil
}

// hasSoftware compiles to an EXISTS over device_software, which the
// device_software_name index covers.
func (c *compiler) hasSoftware(t HasSoftware) (string, error) {
	var b strings.Builder
	b.WriteString("EXISTS (SELECT 1 FROM device_software s WHERE s.device_id = d.id AND lower(s.name) = lower(")
	b.WriteString(c.bind(t.Name))
	b.WriteString(")")

	if t.Op != "" {
		sqlOp, ok := operators[t.Op]
		if !ok {
			return "", fmt.Errorf("groups: unknown operator %q", t.Op)
		}
		if orderingOps[t.Op] {
			// Versions compare as number arrays, because text ordering is
			// simply wrong: '1.10.0' sorts below '1.9.0'. Versions that are
			// not dotted numbers take part in no ordering comparison: the
			// CASE yields NULL for them, and NULL compares as false.
			//
			// numeric rather than int, and inside a CASE rather than behind
			// an AND: a device reporting '1.99999999999' overflowed an int
			// cast, and Postgres does not promise to test an AND's halves in
			// order, so a non-numeric version could reach the cast too. Either
			// failed the whole membership query, so one device's software
			// list could freeze every group that compares versions.
			ver := c.bind(t.Version)
			b.WriteString(" AND " + dottedArray("s.version") + " " + sqlOp + " " + dottedArray(ver))
		} else {
			b.WriteString(" AND s.version " + sqlOp + " " + c.bind(t.Version))
		}
	}
	b.WriteString(")")
	return b.String(), nil
}

// dottedArray turns a dotted-number version into a numeric array, or NULL if
// it is not one. The CASE is what makes the check happen before the cast.
func dottedArray(expr string) string {
	return "(CASE WHEN " + expr + ` ~ '^[0-9]+(\.[0-9]+)*$' THEN string_to_array(` + expr + ", '.')::numeric[] END)"
}
