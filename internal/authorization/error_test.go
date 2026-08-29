package authorization

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lihongjie0209/authorization-service/internal/apperror"
)

func TestTranslateUniqueViolationToConflict(t *testing.T) {
	t.Parallel()
	err := translate(&pgconn.PgError{Code: "23505"})
	var appErr *apperror.Error
	if !errors.As(err, &appErr) || appErr.Code != apperror.CodeConflict {
		t.Fatalf("translate()=%v", err)
	}
}
