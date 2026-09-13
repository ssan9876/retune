package groups

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokIdent
	tokString
	tokNumber
	tokOp
	tokLParen
	tokRParen
	tokComma
)

type token struct {
	kind   tokenKind
	text   string
	number float64
	offset int
}

// ParseError says what was wrong and where, because the console shows it under
// the rule editor while an administrator types.
type ParseError struct {
	Offset  int
	Message string
}

func (e ParseError) Error() string {
	return fmt.Sprintf("at offset %d: %s", e.Offset, e.Message)
}

func errAt(offset int, format string, args ...any) error {
	return ParseError{Offset: offset, Message: fmt.Sprintf(format, args...)}
}

// lex turns a rule into tokens. Keywords, field names and operators are
// case-insensitive; string literals are not.
func lex(rule string) ([]token, error) {
	var out []token
	i := 0
	for i < len(rule) {
		c := rule[i]
		switch {
		case unicode.IsSpace(rune(c)):
			i++

		case c == '(':
			out = append(out, token{kind: tokLParen, text: "(", offset: i})
			i++

		case c == ')':
			out = append(out, token{kind: tokRParen, text: ")", offset: i})
			i++

		case c == ',':
			out = append(out, token{kind: tokComma, text: ",", offset: i})
			i++

		case c == '\'':
			s, next, err := lexString(rule, i)
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: tokString, text: s, offset: i})
			i = next

		case c == '=' || c == '<' || c == '>' || c == '!':
			op, next, err := lexOperator(rule, i)
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: tokOp, text: op, offset: i})
			i = next

		case c >= '0' && c <= '9' || c == '-' || c == '.':
			n, text, next, err := lexNumber(rule, i)
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: tokNumber, text: text, number: n, offset: i})
			i = next

		case isIdentStart(c):
			start := i
			for i < len(rule) && isIdentPart(rule[i]) {
				i++
			}
			out = append(out, token{kind: tokIdent, text: rule[start:i], offset: start})

		default:
			return nil, errAt(i, "unexpected character %q", string(c))
		}
	}
	out = append(out, token{kind: tokEOF, offset: len(rule)})
	return out, nil
}

// lexString reads a single-quoted literal, in which ” is a literal quote.
func lexString(rule string, start int) (string, int, error) {
	var b strings.Builder
	i := start + 1
	for i < len(rule) {
		if rule[i] != '\'' {
			b.WriteByte(rule[i])
			i++
			continue
		}
		if i+1 < len(rule) && rule[i+1] == '\'' {
			b.WriteByte('\'')
			i += 2
			continue
		}
		return b.String(), i + 1, nil
	}
	return "", 0, errAt(start, "unterminated string literal")
}

func lexOperator(rule string, start int) (string, int, error) {
	if start+1 < len(rule) && rule[start+1] == '=' {
		op := rule[start : start+2]
		switch op {
		case "!=", "<=", ">=":
			return op, start + 2, nil
		}
	}
	switch rule[start] {
	case '=', '<', '>':
		return string(rule[start]), start + 1, nil
	}
	return "", 0, errAt(start, "expected an operator, found %q", string(rule[start]))
}

func lexNumber(rule string, start int) (float64, string, int, error) {
	i := start
	if rule[i] == '-' {
		i++
	}
	digits := i
	for i < len(rule) && (rule[i] >= '0' && rule[i] <= '9' || rule[i] == '.') {
		i++
	}
	if i == digits {
		return 0, "", 0, errAt(start, "expected a number")
	}
	text := rule[start:i]
	n, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return 0, "", 0, errAt(start, "%q is not a number", text)
	}
	return n, text, i, nil
}

func isIdentStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || c >= '0' && c <= '9'
}
