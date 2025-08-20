package userstr

import "testing"

func TestDirectBlueprint(t *testing.T) {
	r, err := Parse("tomas~dev")
	if err != nil {
		t.Fatal(err)
	}
	if r.User != "tomas" {
		t.Fatalf("unexpected user: %+v", r)
	}
	if r.Blueprint != "dev" {
		t.Fatalf("unexpected blueprint: %+v", r.Blueprint)
	}
	if r.Params != nil {
		t.Fatalf("expected nil params: %+v", r.Params)
	}
}

func TestParams(t *testing.T) {
	r, err := Parse("tomas~repo=org/svc+ref=feat%2Fabc+mode=inspect")
	if err != nil {
		t.Fatal(err)
	}
	if r.Params["repo"] != "org/svc" {
		t.Fatalf("repo decode failed: %q", r.Params["repo"])
	}
	if r.Params["ref"] != "feat/abc" {
		t.Fatalf("ref decode failed: %q", r.Params["ref"])
	}
	if r.Params["mode"] != "inspect" {
		t.Fatalf("mode mismatch: %q", r.Params["mode"])
	}
}

func TestNoSpec(t *testing.T) {
	r, err := Parse("alice")
	if err != nil {
		t.Fatal(err)
	}
	if r.User != "alice" {
		t.Fatalf("unexpected: %+v", r)
	}
	if r.Blueprint != "" || r.Params != nil {
		t.Fatalf("expected nil bp/params")
	}
}

func TestErrors(t *testing.T) {
	_, err := Parse("noat")
	if err != nil {
		t.Fatal("expected user")
	}
	_, err = Parse("u~a=b=c@h")
	if err == nil {
		t.Fatal("expected error for malformed kv")
	}
}
