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
	deadline, _ := waitCtx.Deadline()
	expired := func() bool { return waitCtx.Err() != nil || !time.Now().Before(deadline) }
	for {
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		actual, reason, err := evaluate()
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		if err != nil || actual != Inconclusive {
			return actual, reason, err
		}
		select {
		case <-ctx.Done():
			return actual, reason, ctx.Err()
		case <-waitCtx.Done():
			if err := ctx.Err(); err != nil {
				return "", "", err
			}
			return actual, reason, nil
		case <-time.After(100 * time.Millisecond):
		}
		// A ready retry timer can race the deadline. Do not start a collector
		// with an expired context or reclassify its deadline cancellation.
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		if expired() {
			return actual, reason, nil
		}
		refreshErr := refresh(waitCtx)
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		if expired() {
			return actual, reason, nil
		}
		if refreshErr != nil {
			return "", "", refreshErr
		}
	}
}
