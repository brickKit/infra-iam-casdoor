package accounts

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// security 03's table for a tightening on the shard's last view: one person within T_tight, two beyond it; a fresh
// view needs no second person whatever its age.
func TestASecondPersonBeyondTTight(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	assert.False(t, secondPerson(time.Time{}, false, now, time.Hour), "a fresh view")
	assert.False(t, secondPerson(now.Add(-59*time.Minute), true, now, time.Hour), "stale, within T_tight")
	assert.False(t, secondPerson(now.Add(-time.Hour), true, now, time.Hour), "exactly T_tight")
	assert.True(t, secondPerson(now.Add(-61*time.Minute), true, now, time.Hour), "beyond T_tight")
}
