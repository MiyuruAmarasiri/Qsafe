package rotation

import (
	"testing"
	"time"
)

func TestManagerRotationByPackets(t *testing.T) {
	now := time.Now()
	m := New(Config{Interval: time.Hour, MaxPackets: 3}, now, 1)

	for i := 0; i < 2; i++ {
		if rotate := m.Record(now); rotate {
			t.Fatalf("unexpected rotate at packet %d", i)
		}
	}

	if rotate := m.Record(now); !rotate {
		t.Fatal("expected rotation by packet threshold")
	}
}

func TestManagerRotationByTime(t *testing.T) {
	start := time.Now()
	m := New(Config{Interval: time.Second, Skew: 0}, start, 1)

	if rotate := m.ShouldRotate(start.Add(500 * time.Millisecond)); rotate {
		t.Fatal("unexpected rotation before interval")
	}

	if rotate := m.ShouldRotate(start.Add(1500 * time.Millisecond)); !rotate {
		t.Fatal("expected rotation after interval")
	}
}
