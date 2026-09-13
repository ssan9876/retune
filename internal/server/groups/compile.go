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
	c := &compiler{args: []any{tenantID, now}}
	// $1 is the tenant and $2 the clock, both referenced by the frame below.
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
	// $2 holds the evaluation time; see Compile.
	column := strings.ReplaceAll(def.sql, clockParam, "$2")
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
			// Versions compare as integer arrays, because text ordering is
			// simply wrong: '1.10.0' sorts below '1.9.0'. Versions that are
			// not dotted numbers take part in no ordering comparison.
			ver := c.bind(t.Version)
			b.WriteString(" AND s.version ~ '^[0-9]+(\\.[0-9]+)*$' AND " + ver + " ~ '^[0-9]+(\\.[0-9]+)*$'")
			b.WriteString(" AND string_to_array(s.version, '.')::int[] " + sqlOp + " string_to_array(" + ver + ", '.')::int[]")
		} else {
			b.WriteString(" AND s.version " + sqlOp + " " + c.bind(t.Version))
		}
	}
	b.WriteString(")")
	return b.String(), nil
}
