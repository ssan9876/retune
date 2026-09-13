// Package groups turns a device-group rule into parameterized SQL and keeps
// dynamic group membership up to date.
package groups

// Node is one expression in a parsed rule.
type Node interface{ node() }

// And matches when both sides match.
type And struct{ Left, Right Node }

// Or matches when either side matches.
type Or struct{ Left, Right Node }

// Not inverts its operand.
type Not struct{ Operand Node }

// Compare tests one device field against a literal.
type Compare struct {
	Field string
	Op    string
	// Exactly one of Text or Number is meaningful, decided by the field's kind.
	Text   string
	Number float64
}

// HasSoftware tests whether a package is installed, optionally comparing its
// version. Op is empty when only the name matters.
type HasSoftware struct {
	Name    string
	Op      string
	Version string
}

func (And) node()         {}
func (Or) node()          {}
func (Not) node()         {}
func (Compare) node()     {}
func (HasSoftware) node() {}

type fieldKind int

const (
	stringField fieldKind = iota
	numberField
)

type fieldDef struct {
	kind fieldKind
	sql  string
}

// clockParam is replaced at compile time with the placeholder holding the
// evaluation time, so that "now" is passed in rather than read from the
// database and tests are deterministic.
const clockParam = "$CLOCK"

// fields is an allowlist, and it is the security boundary of the rule
// language: a rule can only name one of these, and the SQL on the right is the
// only thing that reaches the query. Literals are always bound as placeholders.
var fields = map[string]fieldDef{
	"hostname":      {stringField, "d.hostname"},
	"os_version":    {stringField, "d.os_version"},
	"os_build":      {stringField, "d.os_build"},
	"manufacturer":  {stringField, "d.manufacturer"},
	"model":         {stringField, "d.model"},
	"serial":        {stringField, "d.serial"},
	"agent_version": {stringField, "d.agent_version"},
	"ram_gb":        {numberField, "coalesce(i.ram_gb, 0)"},
	// A device that has never checked in has a NULL last_seen_at, so it
	// matches no last_seen_days comparison.
	"last_seen_days": {numberField, "floor(extract(epoch from (" + clockParam + " - d.last_seen_at)) / 86400)"},
}

// operators is likewise fixed, so an operator can never reach the SQL as text
// taken from input.
var operators = map[string]string{
	"=":    "=",
	"!=":   "<>",
	"<":    "<",
	"<=":   "<=",
	">":    ">",
	">=":   ">=",
	"LIKE": "LIKE",
}

// orderingOps are the operators that imply an ordering, which strings do not
// have here and software versions only have when they are dotted numbers.
var orderingOps = map[string]bool{"<": true, "<=": true, ">": true, ">=": true}

// Fields returns the field names a rule may use, for documentation and the
// console's rule editor.
func Fields() []string {
	out := make([]string, 0, len(fields))
	for name := range fields {
		out = append(out, name)
	}
	return out
}
