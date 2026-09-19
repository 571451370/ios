package resume

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestRingAgainstFullLog(t *testing.T) {
	const max = 4096
	r := NewRing(max)
	var full []byte
	rnd := rand.New(rand.NewSource(1))

	for i := 0; i < 1000; i++ {
		n := 1 + rnd.Intn(max*2)
		chunk := make([]byte, n)
		_, _ = rnd.Read(chunk)
		r.Append(chunk)
		full = append(full, chunk...)

		if got, want := r.End(), uint64(len(full)); got != want {
			t.Fatalf("round %d: End=%d, want %d", i, got, want)
		}
		base := r.Base()
		if r.End()-base > max {
			t.Fatalf("round %d: retained %d bytes, max %d", i, r.End()-base, max)
		}
		if got := r.Slice(0, r.End()); !bytes.Equal(got, full[base:]) {
			t.Fatalf("round %d: retained bytes differ at base=%d", i, base)
		}
	}
}
