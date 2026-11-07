package service

import (
	"fmt"
	"strings"
)

// tokenKind identifies the structural tokens Nginx uses.
type tokenKind uint8

const (
	tokenWord tokenKind = iota
	tokenSemicolon
	tokenLBrace
	tokenRBrace
)

func (k tokenKind) String() string {
	switch k {
	case tokenWord:
		return "word"
	case tokenSemicolon:
		return ";"
	case tokenLBrace:
		return "{"
	case tokenRBrace:
		return "}"
	default:
		return "unknown"
	}
}

type token struct {
	kind  tokenKind
	value string
	line  int
}

// tokenize splits a configuration fragment the way Nginx does:
// whitespace separates words, ';' '{' '}' are structural, quotes group text,
// a backslash escapes the next character, and '#' starts a comment only at
// the beginning of a token (a '#' inside a word is literal).
func tokenize(text string) ([]token, error) {
	var tokens []token
	i, line := 0, 1

	for i < len(text) {
		c := text[i]
		switch c {
		case '\n':
			line++
			i++
		case ' ', '\t', '\r':
			i++
		case '#':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case ';':
			tokens = append(tokens, token{kind: tokenSemicolon, value: ";", line: line})
			i++
		case '{':
			tokens = append(tokens, token{kind: tokenLBrace, value: "{", line: line})
			i++
		case '}':
			tokens = append(tokens, token{kind: tokenRBrace, value: "}", line: line})
			i++
		default:
			startLine := line
			var word strings.Builder
			for i < len(text) {
				c := text[i]
				switch c {
				case '\\':
					i++
					if i >= len(text) {
						return nil, fmt.Errorf("line %d: dangling escape", line)
					}
					if text[i] == '\n' {
						line++
					}
					word.WriteByte(text[i])
					i++
				case '"', '\'':
					quote, quoteLine := c, line
					i++
					closed := false
					for i < len(text) {
						c := text[i]
						if c == '\\' {
							i++
							if i >= len(text) {
								return nil, fmt.Errorf("line %d: dangling escape", line)
							}
							if text[i] == '\n' {
								line++
							}
							word.WriteByte(text[i])
							i++
							continue
						}
						if c == quote {
							i++
							closed = true
							break
						}
						word.WriteByte(c)
						if c == '\n' {
							line++
						}
						i++
					}
					if !closed {
						return nil, fmt.Errorf("line %d: unterminated quote", quoteLine)
					}
				case ' ', '\t', '\r', '\n', ';', '{', '}':
					// End of the word; the outer loop consumes the separator.
					goto wordDone
				default:
					word.WriteByte(c)
					i++
				}
			}
		wordDone:
			tokens = append(tokens, token{kind: tokenWord, value: word.String(), line: startLine})
		}
	}
	return tokens, nil
}

// directive is one parsed configuration statement. Block directives (those
// followed by '{') have block=true.
type directive struct {
	name  string
	args  []string
	line  int
	block bool
	depth int
}

// parseDirectives validates the token structure and returns directives in
// source order. It rejects unbalanced braces, unterminated statements and
// text after a closing brace at depth zero.
func parseDirectives(tokens []token) ([]directive, error) {
	var directives []directive
	depth, i := 0, 0

	for i < len(tokens) {
		tok := tokens[i]
		if tok.kind != tokenWord {
			return nil, fmt.Errorf("line %d: unexpected %q", tok.line, tok.value)
		}

		d := directive{name: strings.ToLower(tok.value), line: tok.line, depth: depth}
		i++
		for i < len(tokens) && tokens[i].kind == tokenWord {
			d.args = append(d.args, tokens[i].value)
			i++
		}
		if i >= len(tokens) {
			return nil, fmt.Errorf("line %d: directive %q is not terminated by ';' or '{'", d.line, d.name)
		}
		switch tokens[i].kind {
		case tokenSemicolon:
			i++
		case tokenLBrace:
			d.block = true
			depth++
			i++
		case tokenRBrace:
			return nil, fmt.Errorf("line %d: directive %q is missing ';'", d.line, d.name)
		}
		directives = append(directives, d)

		for i < len(tokens) && tokens[i].kind == tokenRBrace {
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("line %d: unexpected '}'", tokens[i].line)
			}
			i++
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("unclosed '{' at end of config")
	}
	return directives, nil
}
