// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/k8shell-io/common/pkg/api/client/identity"
	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	"github.com/k8shell-io/identity/internal/mail"
	"github.com/k8shell-io/identity/internal/providers/file"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type sentMail struct{ to, subject, body string }

// newNotifyTestService builds an IdentityService backed by a file provider
// with a user with an email ("alice") and one without ("bob"), no DB.
func newNotifyTestService(t *testing.T, sender func(to, subject, body string) (string, error)) *IdentityService {
	t.Helper()
	dir := t.TempDir()
	users := "users:\n  - username: alice\n    email: alice@example.com\n  - username: bob\n"
	if err := os.WriteFile(filepath.Join(dir, "users.yaml"), []byte(users), 0o600); err != nil {
		t.Fatal(err)
	}
	prov, err := file.NewFileUserProvider(file.FileUserProviderConfig{
		Enabled: true, Files: []string{"users.yaml"},
	}, dir)
	if err != nil {
		t.Fatal(err)
	}
	log := zerolog.Nop()
	srv := &Server{
		log:               &log,
		IdentityProviders: map[string]identity.IdpClient{file.FILE_PROVIDER_NAME: prov},
		notifyMailSender:  sender,
	}
	return NewIdentityService(srv)
}

func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Fatalf("code = %v (err=%v), want %v", got, err, want)
	}
}

func validReq() *identityv1.NotifyUserRequest {
	return &identityv1.NotifyUserRequest{
		Username: "alice", Title: "Heads up", Body: "Your workspace stops soon.",
		Category: "workspace.stop-warning", Workspace: "ws1",
	}
}

func TestMaskEmail(t *testing.T) {
	for in, want := range map[string]string{
		"alice@example.com": "a***@example.com",
		"@example.com":      "***",
		"nope":              "***",
	} {
		if got := maskEmail(in); got != want {
			t.Errorf("maskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNotifyUser_Validation(t *testing.T) {
	svc := newNotifyTestService(t, func(string, string, string) (string, error) { return "ok", nil })
	for name, mutate := range map[string]func(*identityv1.NotifyUserRequest){
		"username": func(r *identityv1.NotifyUserRequest) { r.Username = "" },
		"title":    func(r *identityv1.NotifyUserRequest) { r.Title = "  " },
		"body":     func(r *identityv1.NotifyUserRequest) { r.Body = "" },
		"category": func(r *identityv1.NotifyUserRequest) { r.Category = "" },
	} {
		t.Run(name, func(t *testing.T) {
			r := validReq()
			mutate(r)
			_, err := svc.NotifyUser(context.Background(), r)
			wantCode(t, err, codes.InvalidArgument)
		})
	}
}

func TestNotifyUser_Success(t *testing.T) {
	var got []sentMail
	svc := newNotifyTestService(t, func(to, subject, body string) (string, error) {
		got = append(got, sentMail{to, subject, body})
		return "ok", nil
	})
	if _, err := svc.NotifyUser(context.Background(), validReq()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].to != "alice@example.com" || got[0].subject != "Heads up" {
		t.Fatalf("unexpected mail: %+v", got)
	}
}

func TestNotifyUser_UserErrors(t *testing.T) {
	svc := newNotifyTestService(t, func(string, string, string) (string, error) { return "ok", nil })

	r := validReq()
	r.Username = "nobody"
	_, err := svc.NotifyUser(context.Background(), r)
	wantCode(t, err, codes.NotFound)

	r.Username = "bob"
	_, err = svc.NotifyUser(context.Background(), r)
	wantCode(t, err, codes.FailedPrecondition)
}

func TestNotifyUser_SendFailure(t *testing.T) {
	svc := newNotifyTestService(t, func(string, string, string) (string, error) { return "", errors.New("relay down") })
	_, err := svc.NotifyUser(context.Background(), validReq())
	wantCode(t, err, codes.Unavailable)
}

func TestNotifyUser_SMTPNotConfigured(t *testing.T) {
	svc := newNotifyTestService(t, nil)
	_, err := svc.NotifyUser(context.Background(), validReq())
	wantCode(t, err, codes.Unavailable)
}

func TestSendNotificationEmail_NoHost(t *testing.T) {
	if _, err := mail.SendNotificationEmail(mail.Config{}, "a@b.c", "s\r\nBcc: x@y.z", "b"); err == nil {
		t.Fatal("expected error when smtp host is not configured")
	}
}
