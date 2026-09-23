package suite

import (
	"context"
	"errors"
	"testing"
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
