package main

import (
	"math/rand"
	"strings"
	"testing"
)

func testRoutePeer(id string) PeerDescriptor {
	return PeerDescriptor{
		PeerID:       id,
		IP:           "127.0.0.1",
		DraughtsPort: 5000,
		PubKey:       "pk-" + id,
	}
}

func TestHandleIPCPickFallsBackFromLatestEmptySnapshots(t *testing.T) {
	const (
		selfID = "self"
		nhID   = "node9"
	)

	ring := newSnapshotRing(10)
	ring.Put(NeighborSnapshot{
		OwnerPeerID: nhID,
		Term:        4,
		Active: []PeerDescriptor{
			testRoutePeer("node10"),
			testRoutePeer("node3"),
			testRoutePeer("node7"),
		},
		TimestampMs: 1000,
	})
	ring.Put(NeighborSnapshot{
		OwnerPeerID: nhID,
		Term:        6,
		Active:      nil,
		TimestampMs: 2000,
	})
	ring.Put(NeighborSnapshot{
		OwnerPeerID: nhID,
		Term:        7,
		Active:      nil,
		TimestampMs: 3000,
	})

	d := &daemon{
		cfg: Config{
			SnapshotLimit: 10,
		},
		self:            testRoutePeer(selfID),
		term:            7,
		active:          map[string]PeerDescriptor{nhID: testRoutePeer(nhID)},
		passive:         map[string]PeerDescriptor{},
		neighborHistory: map[string]*snapshotRing{nhID: ring},
		historyMeta:     map[string]int64{},
		selfHistory:     newSnapshotRing(10),
		flushedSelfTerm: map[uint64]struct{}{},
		rnd:             rand.New(rand.NewSource(1)),
	}

	resp := d.handleIPCPick(nhID, 7, "node7")
	if !strings.HasPrefix(resp, "OK ") {
		t.Fatalf("expected PICK success, got %q", resp)
	}
	if !strings.Contains(resp, "term=4") {
		t.Fatalf("expected fallback to term=4 snapshot, got %q", resp)
	}
}

func TestAdvanceTermDoesNotInheritNeighborSnapshots(t *testing.T) {
	const (
		selfID = "self"
		nhID   = "node9"
	)

	ring := newSnapshotRing(10)
	ring.Put(NeighborSnapshot{
		OwnerPeerID: nhID,
		Term:        4,
		Active:      []PeerDescriptor{testRoutePeer("node10")},
		TimestampMs: 1000,
	})

	d := &daemon{
		cfg: Config{
			SnapshotLimit:     10,
			HistoryOwnerLimit: 256,
		},
		self:            testRoutePeer(selfID),
		term:            4,
		active:          map[string]PeerDescriptor{nhID: testRoutePeer(nhID)},
		passive:         map[string]PeerDescriptor{},
		neighborHistory: map[string]*snapshotRing{nhID: ring},
		historyMeta:     map[string]int64{},
		selfHistory:     newSnapshotRing(10),
		flushedSelfTerm: map[uint64]struct{}{4: struct{}{}},
		rnd:             rand.New(rand.NewSource(1)),
	}

	d.advanceTermLocked("test")

	if d.term != 5 {
		t.Fatalf("expected term advanced to 5, got %d", d.term)
	}
	if _, ok := ring.Get(5); ok {
		t.Fatalf("unexpected inherited snapshot at term=5")
	}
}

func TestBuildTwoHopTermViewFiltersFutureSnapshots(t *testing.T) {
	const (
		selfID = "self"
		nhID   = "node9"
	)

	ring := newSnapshotRing(10)
	ring.Put(NeighborSnapshot{
		OwnerPeerID: nhID,
		Term:        4,
		Active:      []PeerDescriptor{testRoutePeer("node10")},
		TimestampMs: 1000,
	})
	ring.Put(NeighborSnapshot{
		OwnerPeerID: nhID,
		Term:        7,
		Active:      []PeerDescriptor{testRoutePeer("node3")},
		TimestampMs: 2000,
	})

	d := &daemon{
		cfg: Config{
			SnapshotLimit: 10,
		},
		self:            testRoutePeer(selfID),
		active:          map[string]PeerDescriptor{nhID: testRoutePeer(nhID)},
		passive:         map[string]PeerDescriptor{},
		neighborHistory: map[string]*snapshotRing{nhID: ring},
		historyMeta:     map[string]int64{},
		selfHistory:     newSnapshotRing(10),
		flushedSelfTerm: map[uint64]struct{}{},
		rnd:             rand.New(rand.NewSource(1)),
	}

	view := d.buildTwoHopTermViewLocked(4)
	if len(view.Active) != 1 {
		t.Fatalf("expected one active neighbor row, got %d", len(view.Active))
	}
	if len(view.Active[0].Snapshots) != 1 {
		t.Fatalf("expected one snapshot at-or-before term 4, got %d", len(view.Active[0].Snapshots))
	}
	if view.Active[0].Snapshots[0].Term != 4 {
		t.Fatalf("expected snapshot term=4, got %d", view.Active[0].Snapshots[0].Term)
	}
}

func TestHandleIPCPickDoesNotUseFutureSnapshotFromCacheFallback(t *testing.T) {
	const (
		selfID = "self"
		nhID   = "node9"
	)

	ring := newSnapshotRing(10)
	ring.Put(NeighborSnapshot{
		OwnerPeerID: nhID,
		Term:        6,
		Active:      []PeerDescriptor{testRoutePeer("node3")},
		TimestampMs: 1000,
	})

	d := &daemon{
		cfg: Config{
			SnapshotLimit: 10,
		},
		self:            testRoutePeer(selfID),
		term:            5,
		active:          map[string]PeerDescriptor{nhID: testRoutePeer(nhID)},
		passive:         map[string]PeerDescriptor{},
		neighborHistory: map[string]*snapshotRing{nhID: ring},
		historyMeta:     map[string]int64{},
		selfHistory:     newSnapshotRing(10),
		flushedSelfTerm: map[uint64]struct{}{},
		rnd:             rand.New(rand.NewSource(1)),
	}

	resp := d.handleIPCPick(nhID, 5, "node7")
	if !strings.Contains(resp, "reason=nh_snapshot_missing") {
		t.Fatalf("expected future cache snapshot to be ignored, got %q", resp)
	}
}
