package suite

import (
	"context"
	"time"
)

// Retry only incomplete evidence, never a conclusive security verdict or an
// operation error. The last incomplete verdict remains a failed acceptance.
func awaitEvidence(ctx context.Context, limit time.Duration, evaluate func() (string, string, error), refresh func(context.Context) error) (string, string, error) {
	waitCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	for {
		actual, reason, err := evaluate()
		if err != nil || actual != Inconclusive {
			return actual, reason, err
		}
		select {
		case <-ctx.Done():
			return actual, reason, ctx.Err()
		case <-waitCtx.Done():
			return actual, reason, nil
		case <-time.After(100 * time.Millisecond):
		}
		if err := refresh(waitCtx); err != nil {
			return "", "", err
		}
	}
}
