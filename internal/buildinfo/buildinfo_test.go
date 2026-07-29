package buildinfo

import "testing"

func TestNormalizedVersion(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "", want: "development"},
		{input: "(devel)", want: "development"},
		{input: " v1.2.3 ", want: "v1.2.3"},
	} {
		if got := normalizedVersion(test.input); got != test.want {
			t.Fatalf("normalizedVersion(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestShortCommit(t *testing.T) {
	info := Info{Commit: "1234567890abcdef"}
	if got := info.ShortCommit(); got != "1234567890ab" {
		t.Fatalf("ShortCommit() = %q", got)
	}
}
