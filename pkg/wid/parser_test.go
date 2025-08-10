package wid

import "testing"

func TestDirectBlueprint(t *testing.T) {
	r, err := Parse("tomas~dev@edge")
	if err != nil {
		t.Fatal(err)
	}
	if r.User != "tomas" || r.Addr != "edge" {
		t.Fatalf("unexpected user/addr: %+v", r)
	}
	if r.Blueprint == nil || *r.Blueprint != "dev" {
		t.Fatalf("unexpected blueprint: %+v", r.Blueprint)
	}
	if r.Params != nil {
		t.Fatalf("expected nil params: %+v", r.Params)
	}
}

func TestParams(t *testing.T) {
	r, err := Parse("tomas~repo=org/svc+ref=feat%2Fabc+mode=inspect@edge")
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
	r, err := Parse("alice@host")
	if err != nil {
		t.Fatal(err)
	}
	if r.User != "alice" || r.Addr != "host" {
		t.Fatalf("unexpected: %+v", r)
	}
	if r.Blueprint != nil || r.Params != nil {
		t.Fatalf("expected nil bp/params")
	}
}

func TestErrors(t *testing.T) {
	_, err := Parse("noat")
	if err == nil {
		t.Fatal("expected error for missing @")
	}
	_, err = Parse("@addr")
	if err == nil {
		t.Fatal("expected error for empty user")
	}
	_, err = Parse("user@")
	if err == nil {
		t.Fatal("expected error for empty addr")
	}
	_, err = Parse("u~a=b=c@h")
	if err == nil {
		t.Fatal("expected error for malformed kv")
	}
}
