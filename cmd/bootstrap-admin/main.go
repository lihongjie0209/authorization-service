package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/lihongjie0209/authorization-service/internal/bootstrap"
	"github.com/lihongjie0209/authorization-service/internal/config"
	"github.com/lihongjie0209/authorization-service/internal/database"
	"github.com/spf13/cobra"
)

type options struct {
	configPath       string
	profile          string
	userID           string
	serviceAccountID string
}

type grantFunc func(context.Context, options) (bootstrap.Result, error)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(execute(ctx, os.Args[1:], os.Stdout, os.Stderr, run))
}

type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func execute(ctx context.Context, args []string, stdout, stderr io.Writer, grant grantFunc) int {
	command := newCommand(grant)
	command.SetArgs(args)
	command.SetOut(stdout)
	command.SetErr(stderr)
	if err := command.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(stderr, err)
		var invalidUsage usageError
		if errors.As(err, &invalidUsage) {
			return 2
		}
		return 1
	}
	return 0
}

func newCommand(grant grantFunc) *cobra.Command {
	var opts options
	command := &cobra.Command{
		Use:   "authorization-bootstrap-admin",
		Short: "Grant the reserved platform super-admin role",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return usageError{err: err}
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			userID := strings.TrimSpace(opts.userID)
			serviceAccountID := strings.TrimSpace(opts.serviceAccountID)
			if (userID == "") == (serviceAccountID == "") {
				return usageError{err: errors.New("exactly one of --user-id or --service-account-id is required")}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := grant(cmd.Context(), opts)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		},
	}
	command.SetOut(os.Stdout)
	command.SetErr(os.Stderr)
	command.Flags().StringVar(&opts.configPath, "config", "config/config.yaml", "configuration file path")
	command.Flags().StringVar(&opts.profile, "env", "", "active environment profile")
	command.Flags().StringVar(&opts.userID, "user-id", "", "global Identity user ID to grant")
	command.Flags().StringVar(&opts.serviceAccountID, "service-account-id", "", "Identity service-account ID to grant")
	command.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageError{err: err} })
	return command
}

func run(ctx context.Context, opts options) (bootstrap.Result, error) {
	cfg, err := config.LoadWithProfile(opts.configPath, opts.profile)
	if err != nil {
		return bootstrap.Result{}, fmt.Errorf("load configuration: %w", err)
	}
	if !cfg.Database.Enabled {
		return bootstrap.Result{}, errors.New("database must be enabled")
	}
	db, err := database.Open(ctx, cfg.Database)
	if err != nil {
		return bootstrap.Result{}, fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()
	subjectID, subjectType := opts.userID, "user"
	if opts.serviceAccountID != "" {
		subjectID, subjectType = opts.serviceAccountID, "service_account"
	}
	return bootstrap.GrantPlatformSuperAdmin(ctx, db, subjectID, subjectType)
}
