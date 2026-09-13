package groups

import (
	"strings"
)

const (
	// MaxRuleLength and MaxRuleDepth turn a mistake into a clear error rather
	// than a query that takes the database down. Rules are written by
	// administrators, not end users.
	MaxRuleLength = 2000
	MaxRuleDepth  = 20
)

// Parse turns a rule into an AST, reporting where and why it failed.
func Parse(rule string) (Node, error) {
	if len(rule) > MaxRuleLength {
		return nil, errAt(MaxRuleLength, "a rule may be at most %d characters", MaxRuleLength)
	}
	if strings.TrimSpace(rule) == "" {
		return nil, errAt(0, "a rule cannot be empty")
	}
	toks, err := lex(rule)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.parseOr(0)
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, errAt(p.peek().offset, "unexpected %s", describe(p.peek()))
	}
	return n, nil
}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token { return p.toks[p.pos] }

func (p *parser) next() token {
	t := p.toks[p.pos]
	if t.kind != tokEOF {
		p.pos++
	}
	return t
}

// keywordIs reports whether the current token is the given keyword, ignoring
// case.
func (p *parser) keywordIs(word string) bool {
	t := p.peek()
	return t.kind == tokIdent && strings.EqualFold(t.text, word)
}

func (p *parser) parseOr(depth int) (Node, error) {
	if depth > MaxRuleDepth {
		return nil, errAt(p.peek().offset, "a rule may be at most %d levels deep", MaxRuleDepth)
	}
	left, err := p.parseAnd(depth)
	if err != nil {
		return nil, err
	}
	for p.keywordIs("OR") {
		p.next()
		right, err := p.parseAnd(depth)
		if err != nil {
			return nil, err
		}
		left = Or{Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseAnd(depth int) (Node, error) {
	left, err := p.parseNot(depth)
	if err != nil {
		return nil, err
	}
	for p.keywordIs("AND") {
		p.next()
		right, err := p.parseNot(depth)
		if err != nil {
			return nil, err
		}
		left = And{Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseNot(depth int) (Node, error) {
	if p.keywordIs("NOT") {
		p.next()
		operand, err := p.parseNot(depth + 1)
		if err != nil {
			return nil, err
		}
		return Not{Operand: operand}, nil
	}
	return p.parsePrimary(depth)
}

func (p *parser) parsePrimary(depth int) (Node, error) {
	t := p.peek()
	switch {
	case t.kind == tokLParen:
		p.next()
		inner, err := p.parseOr(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, errAt(p.peek().offset, "expected a closing parenthesis")
		}
		p.next()
		return inner, nil

	case t.kind == tokIdent && strings.EqualFold(t.text, "has_software"):
		return p.parseHasSoftware()

	case t.kind == tokIdent:
		return p.parseComparison()
	}
	return nil, errAt(t.offset, "expected a condition, found %s", describe(t))
}

func (p *parser) parseComparison() (Node, error) {
	nameTok := p.next()
	name := strings.ToLower(nameTok.text)
	def, ok := fields[name]
	if !ok {
		return nil, errAt(nameTok.offset, "unknown field %q", nameTok.text)
	}

	op, err := p.parseOperator()
	if err != nil {
		return nil, err
	}
	opTok := p.toks[p.pos-1]

	switch def.kind {
	case stringField:
		if orderingOps[op] {
			return nil, errAt(opTok.offset, "%s is text, so it cannot be compared with %s", name, op)
		}
	case numberField:
		if op == "LIKE" {
			return nil, errAt(opTok.offset, "%s is a number, so it cannot be compared with LIKE", name)
		}
	}

	lit := p.next()
	switch def.kind {
	case stringField:
		if lit.kind != tokString {
			return nil, errAt(lit.offset, "%s is text, so it needs a quoted value", name)
		}
		return Compare{Field: name, Op: op, Text: lit.text}, nil
	default:
		if lit.kind != tokNumber {
			return nil, errAt(lit.offset, "%s is a number, so it needs an unquoted number", name)
		}
		return Compare{Field: name, Op: op, Number: lit.number}, nil
	}
}

func (p *parser) parseOperator() (string, error) {
	t := p.peek()
	if t.kind == tokIdent && strings.EqualFold(t.text, "LIKE") {
		p.next()
		return "LIKE", nil
	}
	if t.kind != tokOp {
		return "", errAt(t.offset, "expected a comparison operator, found %s", describe(t))
	}
	p.next()
	if _, ok := operators[t.text]; !ok {
		return "", errAt(t.offset, "unknown operator %q", t.text)
	}
	return t.text, nil
}

// parseHasSoftware reads has_software('name') or has_software('name', op, 'version').
func (p *parser) parseHasSoftware() (Node, error) {
	fn := p.next()
	if p.peek().kind != tokLParen {
		return nil, errAt(p.peek().offset, "has_software needs parentheses")
	}
	p.next()

	nameTok := p.next()
	if nameTok.kind != tokString {
		return nil, errAt(nameTok.offset, "has_software needs a quoted package name")
	}
	out := HasSoftware{Name: nameTok.text}

	if p.peek().kind == tokComma {
		p.next()
		opTok := p.next()
		if opTok.kind != tokString {
			return nil, errAt(opTok.offset, "the version operator must be quoted, as in has_software('x', '>=', '1.2')")
		}
		op := strings.ToUpper(opTok.text)
		if _, ok := operators[op]; !ok || op == "LIKE" {
			return nil, errAt(opTok.offset, "%q is not a version comparison operator", opTok.text)
		}
		if p.peek().kind != tokComma {
			return nil, errAt(p.peek().offset, "a version operator needs a version, as in has_software('x', '>=', '1.2')")
		}
		p.next()
		verTok := p.next()
		if verTok.kind != tokString {
			return nil, errAt(verTok.offset, "the version must be quoted")
		}
		out.Op, out.Version = op, verTok.text
	}

	if p.peek().kind != tokRParen {
		return nil, errAt(p.peek().offset, "expected a closing parenthesis for has_software")
	}
	p.next()
	_ = fn
	return out, nil
}

func describe(t token) string {
	switch t.kind {
	case tokEOF:
		return "the end of the rule"
	case tokString:
		return "a quoted value"
	case tokNumber:
		return "a number"
	default:
		if t.text == "" {
			return "nothing"
		}
		return "\"" + t.text + "\""
	}
}
