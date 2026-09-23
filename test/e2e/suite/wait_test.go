package suite

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestEvidenceWaitPreservesVerdictsAndErrors(t *testing.T) {
	for _, actual := range []string{Satisfied, Violated, ExecutionError} {
		t.Run(actual, func(t *testing.T) {
			got, _, err := awaitEvidence(t.Context(), time.Second, func() (string, string, error) { return actual, "original", nil }, func(context.Context) error { t.Fatal("terminal result retried"); return nil })
			if err != nil || got != actual {
				t.Fatalf("got %s, %v", got, err)
			}
		})
	}
	t.Run("late logs", func(t *testing.T) {
		actual := Inconclusive
		got, _, err := awaitEvidence(t.Context(), time.Second, func() (string, string, error) { return actual, "", nil }, func(context.Context) error { actual = Satisfied; return nil })
		if err != nil || got != Satisfied {
			t.Fatalf("got %s, %v", got, err)
		}
	})
	t.Run("incomplete deadline", func(t *testing.T) {
		got, reason, err := awaitEvidence(t.Context(), time.Millisecond, func() (string, string, error) { return Inconclusive, "missing logs", nil }, func(context.Context) error { t.Fatal("refresh after deadline"); return nil })
		if err != nil || got != Inconclusive || reason != "missing logs" {
			t.Fatalf("got %s, %s, %v", got, reason, err)
		}
	})
	t.Run("collector failure", func(t *testing.T) {
		failure := errors.New("log collector failed")
		_, _, err := awaitEvidence(t.Context(), time.Second, func() (string, string, error) { return Inconclusive, "", nil }, func(context.Context) error { return failure })
		if !errors.Is(err, failure) {
			t.Fatalf("collector error hidden: %v", err)
		}
	})
}

func TestEvidenceWaitDeadlineDuringCollection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		got, reason, err := awaitEvidence(t.Context(), time.Second, func() (string, string, error) { return Inconclusive, "missing evidence", nil }, func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
		if err != nil || got != Inconclusive || reason != "missing evidence" {
			t.Fatalf("got %s, %s, %v", got, reason, err)
		}
	})
}

func TestEvidenceWaitDoesNotStartCollectorAtDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for range 32 {
			got, _, err := awaitEvidence(t.Context(), 100*time.Millisecond, func() (string, string, error) { return Inconclusive, "missing evidence", nil }, func(context.Context) error { t.Fatal("collector started at deadline"); return nil })
			if err != nil || got != Inconclusive {
				t.Fatalf("got %s, %v", got, err)
			}
		}
	})
}

func TestEvidenceWaitPreservesParentCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		_, _, err := awaitEvidence(ctx, time.Second, func() (string, string, error) { return Inconclusive, "missing evidence", nil }, func(context.Context) error { cancel(); return ctx.Err() })
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("parent cancellation hidden: %v", err)
		}
	})
}
