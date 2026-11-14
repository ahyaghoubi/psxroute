package rules

import "testing"

func TestMatch(t *testing.T) {
	s, err := Build([]string{"ea"}, []string{"*.Example.org.", "callofduty.com"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host   string
		ok     bool
		source string
	}{
		{"ea.com", true, "ea"},
		{"accounts.ea.com.", true, "ea"},
		{"GATEWAY.EA.COM", true, "ea"},
		{"tea.com", false, ""},
		{"ea.com.evil.net", false, ""},
		{"example.org", true, "config"},
		{"a.b.example.org", true, "config"},
		{"profile.callofduty.com", true, "config"},
		{"playstation.net", false, ""},
		{"", false, ""},
	}
	for _, c := range cases {
		src, ok := s.Match(c.host)
		if ok != c.ok || src != c.source {
			t.Errorf("Match(%q) = %q, %v; want %q, %v", c.host, src, ok, c.source, c.ok)
		}
	}
}

func TestBuildUnknownPack(t *testing.T) {
	if _, err := Build([]string{"nope"}, nil); err == nil {
		t.Fatal("want error for unknown pack")
	}
}

func TestPacksLoad(t *testing.T) {
	packs, err := Packs()
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) == 0 {
		t.Fatal("no built-in packs")
	}
	for _, p := range packs {
		if p.Name == "" || len(p.Hosts) == 0 {
			t.Errorf("pack %+v is empty", p)
		}
	}
}

func TestNilSet(t *testing.T) {
	var s *Set
	if _, ok := s.Match("ea.com"); ok || s.Len() != 0 {
		t.Fatal("nil set should match nothing")
	}
}

func TestAddRemove(t *testing.T) {
	s, err := Build([]string{"ea"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Add("*.Example.Org", SourceAdded); !ok || err != nil {
		t.Fatalf("Add = %v, %v", ok, err)
	}
	if ok, _ := s.Add("example.org", SourceAdded); ok {
		t.Fatal("second Add should report false")
	}
	if src, ok := s.Match("cdn.example.org"); !ok || src != SourceAdded {
		t.Fatalf("Match = %q, %v", src, ok)
	}
	if s.Remove("ea.com", SourceAdded) {
		t.Fatal("removed a pack domain as if it were added")
	}
	if !s.Remove("example.org", SourceAdded) {
		t.Fatal("Remove failed")
	}
	if _, ok := s.Match("cdn.example.org"); ok {
		t.Fatal("still routed after Remove")
	}
	for _, bad := range []string{"", "com", "a..b", "exa mple.com", "1.2.3.4/8"} {
		if _, err := s.Add(bad, SourceAdded); err == nil {
			t.Errorf("Add(%q) should fail", bad)
		}
	}
}

func TestGroup(t *testing.T) {
	for in, want := range map[string]string{
		"accounts.ea.com":         "ea.com",
		"ea.com":                  "ea.com",
		"eaassets-a.akamaihd.net": "akamaihd.net",
		"www.bbc.co.uk":           "bbc.co.uk",
		"localhost":               "localhost",
		"Prod.Demonware.Net.":     "demonware.net",
	} {
		if got := Group(in); got != want {
			t.Errorf("Group(%q) = %q, want %q", in, got, want)
		}
	}
}
