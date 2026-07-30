package authentication

import "testing"

func TestSnapshotResolvesUniqueTokenContext(t *testing.T) {
	token := "governed-token-with-at-least-32-random-bytes"
	snapshot, err := NewSnapshot([]Record{{
		Context: Context{Mode: ModeGoverned, ClientID: "customer-a"},
		Token:   token,
	}})
	if err != nil {
		t.Fatal(err)
	}
	selector := Selector(token)
	record, exists := snapshot.Resolve(selector[:])
	if !exists {
		t.Fatal("authentication record was not resolved")
	}
	if record.Context.Mode != ModeGoverned || record.Context.ClientID != "customer-a" {
		t.Fatalf("unexpected authentication context: %+v", record.Context)
	}
}

func TestSnapshotRejectsDuplicateToken(t *testing.T) {
	token := "duplicate-token-with-at-least-32-random-bytes"
	_, err := NewSnapshot([]Record{
		{Context: Context{Mode: ModeGoverned, ClientID: "a"}, Token: token},
		{Context: Context{Mode: ModeManaged, ClientID: "b"}, Token: token},
	})
	if err == nil {
		t.Fatal("duplicate Token was accepted")
	}
}

func TestStorePreservesAndRotatesPerRecordGeneration(t *testing.T) {
	token := "governed-token-with-at-least-32-random-bytes"
	initial, err := NewSnapshot([]Record{{
		Context: Context{Mode: ModeGoverned, ClientID: "customer-a"},
		Token:   token,
	}})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial)
	selector := Selector(token)
	first, exists := store.Resolve(selector[:])
	if !exists || first.Context.Generation == 0 {
		t.Fatal("initial record generation was not assigned")
	}

	unchanged, err := NewSnapshot([]Record{{
		Context: Context{Mode: ModeGoverned, ClientID: "customer-a"},
		Token:   token,
	}})
	if err != nil {
		t.Fatal(err)
	}
	store.Replace(unchanged)
	second, _ := store.Resolve(selector[:])
	if second.Context.Generation != first.Context.Generation {
		t.Fatal("unchanged record generation was rotated")
	}

	rotated, err := NewSnapshot([]Record{{
		Context: Context{Mode: ModeGoverned, ClientID: "customer-a"},
		Token:   token,
	}})
	if err != nil {
		t.Fatal(err)
	}
	store.ReplaceRevoking(rotated, []Context{first.Context})
	third, _ := store.Resolve(selector[:])
	if third.Context.Generation == first.Context.Generation {
		t.Fatal("revoked record generation was not rotated")
	}
	if store.IsCurrent(first.Context) {
		t.Fatal("revoked authentication context remained current")
	}
	if !store.IsCurrent(third.Context) {
		t.Fatal("replacement authentication context is not current")
	}
}
