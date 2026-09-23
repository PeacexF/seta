package tags

import "testing"

func TestParse(t *testing.T) {
	l, err := Parse(" v=DKIM1 ; K = rsa;p=abc; ", false)
	if err != nil || len(l) != 3 || l[1] != (Tag{"K", "rsa"}) {
		t.Fatalf("got %v, %v", l, err)
	}
	if v, ok := l.Get("p"); !ok || v != "abc" {
		t.Errorf("Get(p) = %q %v", v, ok)
	}
	if l, _ := Parse("A=1", true); l[0].Name != "a" {
		t.Errorf("fold: %v", l)
	}
	for _, bad := range []string{"a=1;;b=2", "a", "1a=2", "a=1;a=2", "=x"} {
		if _, err := Parse(bad, false); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
	if _, err := Parse("A=1;a=2", true); err == nil {
		t.Error("duplicate after folding accepted")
	}
}

func FuzzParse(f *testing.F) {
	f.Add("v=DMARC1; p=none; rua=mailto:a@b.c")
	f.Fuzz(func(t *testing.T, s string) {
		l, err := Parse(s, true)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, tag := range l {
			if seen[tag.Name] {
				t.Fatalf("duplicate %q returned", tag.Name)
			}
			seen[tag.Name] = true
		}
	})
}
