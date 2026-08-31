package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lihongjie0209/authorization-service/internal/bootstrap"
)

func TestCommandEmitsMachineReadableResult(t *testing.T) {
	t.Parallel()
	var received options
	command := newCommand(func(_ context.Context, opts options) (bootstrap.Result, error) {
		received = opts
		return bootstrap.Result{BindingID: "binding-1", SubjectID: opts.userID, SubjectType: "user", RoleID: "role-1"}, nil
	})
	output := new(bytes.Buffer)
	command.SetOut(output)
	command.SetErr(new(bytes.Buffer))
	command.SetArgs([]string{"--config", "custom.yaml", "--env", "production", "--user-id", "user-1"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if received.configPath != "custom.yaml" || received.profile != "production" || received.userID != "user-1" || !strings.Contains(output.String(), `"binding_id":"binding-1"`) {
		t.Fatalf("options = %+v output = %q", received, output.String())
	}
}

func TestCommandRejectsMissingOrConflictingSubjects(t *testing.T) {
	t.Parallel()
	grant := func(context.Context, options) (bootstrap.Result, error) {
		return bootstrap.Result{}, errors.New("must not run")
	}
	for _, args := range [][]string{{}, {"--user-id", "user-1", "--service-account-id", "service-1"}} {
		command := newCommand(grant)
		command.SetArgs(args)
		if err := command.Execute(); err == nil {
			t.Fatalf("Execute(%v) error = nil", args)
		}
	}
}

func TestExecuteUsesStableExitCodes(t *testing.T) {
	t.Parallel()
	grant := func(context.Context, options) (bootstrap.Result, error) {
		return bootstrap.Result{}, errors.New("database unavailable")
	}
	if code := execute(t.Context(), nil, new(bytes.Buffer), new(bytes.Buffer), grant); code != 2 {
		t.Fatalf("usage exit code = %d, want 2", code)
	}
	if code := execute(t.Context(), []string{"--user-id", "user-1"}, new(bytes.Buffer), new(bytes.Buffer), grant); code != 1 {
		t.Fatalf("runtime exit code = %d, want 1", code)
	}
	if code := execute(t.Context(), []string{"--user-id", "user-1"}, new(bytes.Buffer), new(bytes.Buffer), func(context.Context, options) (bootstrap.Result, error) { return bootstrap.Result{}, nil }); code != 0 {
		t.Fatalf("success exit code = %d, want 0", code)
	}
}
