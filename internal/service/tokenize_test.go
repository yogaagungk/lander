package service

import "testing"

func TestTokenizeNginxSemantics(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string // kind:value for words, or the raw separator
	}{
		{
			name: "quoted semicolon stays inside the word",
			in:   `add_header X "a;b";`,
			want: []string{"word:add_header", "word:X", "word:a;b", ";"},
		},
		{
			name: "escaped semicolon stays inside the word",
			in:   `add_header X a\;b;`,
			want: []string{"word:add_header", "word:X", "word:a;b", ";"},
		},
		{
			name: "hash inside a word is literal",
			in:   `add_header X a#b;`,
			want: []string{"word:add_header", "word:X", "word:a#b", ";"},
		},
		{
			name: "hash at token start starts a comment",
			in:   "add_header X ok; # include /etc/passwd\n",
			want: []string{"word:add_header", "word:X", "word:ok", ";"},
		},
		{
			name: "braces inside quotes are word content",
			in:   `add_header X "{";`,
			want: []string{"word:add_header", "word:X", "word:{", ";"},
		},
		{
			name: "structural braces and blocks",
			in:   "server { location / { proxy_pass http://127.0.0.1:3000; } }",
			want: []string{"word:server", "{", "word:location", "word:/", "{",
				"word:proxy_pass", "word:http://127.0.0.1:3000", ";", "}", "}"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := tokenize(tt.in)
			if err != nil {
				t.Fatalf("tokenize: %v", err)
			}
			if len(tokens) != len(tt.want) {
				t.Fatalf("tokens = %v, want %v", tokenStrings(tokens), tt.want)
			}
			for i, token := range tokens {
				got := token.value
				if token.kind == tokenWord {
					got = "word:" + token.value
				}
				if got != tt.want[i] {
					t.Errorf("token %d = %q, want %q", i, got, tt.want[i])
				}
			}
		})
	}
}

func TestTokenizeRejectsUnterminatedQuote(t *testing.T) {
	if _, err := tokenize(`add_header X "unterminated;`); err == nil {
		t.Fatal("expected an error for an unterminated quote")
	}
}

func TestParseDirectivesStructure(t *testing.T) {
	tokens, err := tokenize(`server {
    listen 80;
    server_name a.example.com;
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}`)
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	directives, err := parseDirectives(tokens)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string]int{
		"server":      0,
		"listen":      1,
		"server_name": 1,
		"location":    1,
		"proxy_pass":  2,
	}
	if len(directives) != len(want) {
		t.Fatalf("directives = %d, want %d", len(directives), len(want))
	}
	for _, d := range directives {
		if depth, ok := want[d.name]; !ok || d.depth != depth {
			t.Errorf("directive %s depth = %d, want %d", d.name, d.depth, want[d.name])
		}
	}

	tokens, err = tokenize("server { listen 80; ")
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	if _, err := parseDirectives(tokens); err == nil {
		t.Error("expected an error for an unclosed block")
	}
}

func tokenStrings(tokens []token) []string {
	out := make([]string, len(tokens))
	for i, token := range tokens {
		if token.kind == tokenWord {
			out[i] = "word:" + token.value
		} else {
			out[i] = token.value
		}
	}
	return out
}
