package engine

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// follower clock 60s BEHIND leader. Leader's expire op arrives while the
// follower clock is still before the deadline: applied immediately.
func TestTTL_R4_FollowerClockBehindAppliesExpireAtOnce(t *testing.T) {
	p := newPair(t)
	mustSet(t, p.L, "s.red-xai-db-qs-ls:B.V", num(1), SetOpts{TTLSeconds: 30})
	p.ship()
	p.LC.Advance(60 * time.Second) // leader +60, follower stays at T0 (60s behind)
	p.L.sweepNow()
	p.ship()
	if p.fEntry(qsls, seg("B"), seg("V")) != nil {
		t.Fatal("expire op not applied on a follower whose clock is behind")
	}
	if !absentOrNell(t, p.F, "s.red-xai-db-qs-ls:B.V") {
		t.Fatal("still readable")
	}
}

// Query on an expired sliding key must not slide/revive it.
func TestTTL_E4Q_ExpiredQueryNeverRevives(t *testing.T) {
	clk := newFakeClock()
	db := open(t, t.TempDir(), Config{Clock: clk.Now})
	defer db.Close()
	mustSet(t, db, qsF+"Sess[ID=1].B", num(1), SetOpts{TTLSeconds: 10, Sliding: true})
	clk.Advance(10 * time.Second)
	for i := 0; i < 3; i++ {
		if r, _ := db.Query(qsF + "Sess[ID=*]"); len(r) != 0 {
			t.Fatalf("query %d returned expired data: %v", i, r)
		}
		if !absentOrNell(t, db, qsF+"Sess[ID=1].B") {
			t.Fatalf("get %d revived key", i)
		}
	}
}

// randomized model check of fixed/sliding TTL semantics + leader->follower replication.
func TestTTL_Model_TTLRandomized(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		rnd := rand.New(rand.NewSource(seed))
		p := newPair(t)
		type m struct {
			val   float64
			dl    int64
			slide bool
			secs  int64
			alive bool
		}
		model := map[int]*m{}
		now := func() int64 { return p.LC.Now().UnixMilli() }
		for step := 0; step < 400; step++ {
			k := rnd.Intn(8) + 1
			path := fmt.Sprintf("q.red-xai-db-qs:Sess[ID=%d].V", k)
			switch rnd.Intn(5) {
			case 0, 1:
				ttl := rnd.Intn(20) + 1
				sl := rnd.Intn(2) == 0
				v := float64(rnd.Intn(1000))
				mustSet(t, p.L, path, num(v), SetOpts{TTLSeconds: ttl, Sliding: sl})
				model[k] = &m{val: v, dl: now() + int64(ttl)*1000, slide: sl, secs: int64(ttl), alive: true}
			case 2:
				v, err := p.L.Get(path)
				me := model[k]
				live := me != nil && me.alive && now() < me.dl
				if live {
					if err != nil || v.IsNell() || v.Num != me.val {
						t.Fatalf("seed %d step %d: Get k=%d got (%v,%v) want %v", seed, step, k, v, err, me.val)
					}
					if me.slide {
						me.dl = now() + me.secs*1000
					}
				} else {
					if err == nil && !v.IsNell() {
						t.Fatalf("seed %d step %d: Get k=%d returned %v for expired/absent key (now=%d dl=%v)", seed, step, k, v, now(), me)
					}
					if me != nil {
						me.alive = false
					}
				}
			case 3:
				d := time.Duration(rnd.Intn(8000)+1) * time.Millisecond
				p.LC.Advance(d)
				p.FC.Advance(d)
				if rnd.Intn(2) == 0 {
					p.L.sweepNow()
				}
			case 4:
				p.ship()
			}
		}
		p.L.sweepNow()
		p.ship()
		// follower must never show something the leader has expired AFTER shipping (same clock): compare liveness
		for k := 1; k <= 8; k++ {
			path := fmt.Sprintf("q.red-xai-db-qs:Sess[ID=%d].V", k)
			me := model[k]
			live := me != nil && me.alive && now() < me.dl
			fv, ferr := p.F.Get(path)
			fLive := ferr == nil && !fv.IsNell()
			if fLive && !live {
				t.Fatalf("seed %d: follower shows k=%d but model says dead (leader expired)", seed, k)
			}
			if live && !fLive {
				t.Fatalf("seed %d: follower hides k=%d which is live on leader (dl=%d now=%d)", seed, k, me.dl, now())
			}
		}
	}
}

// concurrent Set/Get/Delete/Query + real clock sweeper under -race.
func TestTTL_Stress_ConcurrentTTL(t *testing.T) {
	db := open(t, t.TempDir(), Config{SweepMS: 5})
	defer db.Close()
	stop := time.Now().Add(1500 * time.Millisecond)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(g)))
			for time.Now().Before(stop) {
				k := r.Intn(30)
				path := fmt.Sprintf("%sSess[ID=%d].V", qsF, k)
				switch r.Intn(4) {
				case 0:
					_ = db.Set(path, num(1), SetOpts{TTLSeconds: 1, Sliding: r.Intn(2) == 0})
				case 1:
					_, _ = db.Get(path)
				case 2:
					_ = db.Delete(fmt.Sprintf("%sSess[ID=%d]", qsF, k))
				case 3:
					_, _ = db.Query(qsF + "Sess[ID=*]")
				}
			}
		}(g)
	}
	wg.Wait()
}
