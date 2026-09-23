package groups_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/groups"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

// device creates an active device with some inventory, so rules have
// something to match on.
func device(t *testing.T, st *store.Store, hostname string, ramGB float64, software ...store.Software) store.Device {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: hostname, Serial: hostname + "-SN",
		OSVersion: "Microsoft Windows 11 Pro", Status: store.DeviceActive,
		CertSerial: hostname, CertExpiresAt: now.Add(24 * time.Hour), EnrolledAt: now,
	}
	if err := st.Q().CreateDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := st.Q().UpsertInventory(ctx, store.DeviceInventory{
		DeviceID: d.ID, CollectedAt: now, ReceivedAt: now,
		Hash: hostname, SoftwareHash: hostname, Data: []byte(`{}`), RAMGB: ramGB,
	}); err != nil {
		t.Fatal(err)
	}
	if len(software) > 0 {
		if err := st.Q().ReplaceSoftware(ctx, d.ID, software); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Q().RecordCheckin(ctx, store.DefaultTenantID, d.ID, "1.0.0", now); err != nil {
		t.Fatal(err)
	}
	return d
}

func service(st *store.Store) *groups.Service {
	return &groups.Service{Store: st, Now: time.Now}
}

func TestEvaluateDynamicGroup(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	big := device(t, st, "BIG", 32)
	small := device(t, st, "SMALL", 8)

	g, err := svc.Create(ctx, groups.NewGroup{
		Name: "Plenty of RAM", Kind: store.GroupDynamic, Rule: "ram_gb >= 16", Actor: "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	members, total, err := st.Q().ListGroupMembers(ctx, g.ID, store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || members[0].ID != big.ID {
		t.Fatalf("want only %s, got %d members %v", big.Hostname, total, members)
	}

	// Giving the small machine more memory moves it into the group when its
	// inventory is re-evaluated.
	if err := st.Q().UpsertInventory(ctx, store.DeviceInventory{
		DeviceID: small.ID, CollectedAt: time.Now(), ReceivedAt: time.Now(),
		Hash: "x", SoftwareHash: "x", Data: []byte(`{}`), RAMGB: 64,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.EvaluateDevice(ctx, small.ID); err != nil {
		t.Fatal(err)
	}
	if _, total, err = st.Q().ListGroupMembers(ctx, g.ID, store.Page{}); err != nil {
		t.Fatal(err)
	} else if total != 2 {
		t.Fatalf("want both devices after the upgrade, got %d", total)
	}
}

// TestRulesRunAgainstPostgres is the check that every compiled form is valid
// SQL, not just well-formed Go.
func TestRulesRunAgainstPostgres(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	device(t, st, "DESKTOP-A", 32,
		store.Software{Name: "Google Chrome", Version: "119.0.6045"},
		store.Software{Name: "7-Zip", Version: "23.01"})
	device(t, st, "LAPTOP-B", 8,
		store.Software{Name: "Google Chrome", Version: "121.0.6167"})

	cases := map[string]struct {
		rule string
		want int
	}{
		"hostname prefix":      {`hostname LIKE 'DESKTOP-%'`, 1},
		"negation":             {`NOT hostname LIKE 'DESKTOP-%'`, 1},
		"numeric":              {`ram_gb >= 16`, 1},
		"and":                  {`ram_gb >= 4 AND os_version LIKE '%Windows 11%'`, 2},
		"or":                   {`hostname = 'DESKTOP-A' OR hostname = 'LAPTOP-B'`, 2},
		"software present":     {`has_software('7-Zip')`, 1},
		"software absent":      {`has_software('Nonexistent App')`, 0},
		"software name case":   {`has_software('google chrome')`, 2},
		"version below":        {`has_software('Google Chrome', '<', '120.0.0')`, 1},
		"version at or above":  {`has_software('Google Chrome', '>=', '120.0.0')`, 1},
		"version equality":     {`has_software('7-Zip', '=', '23.01')`, 1},
		"last seen":            {`last_seen_days < 1`, 2},
		"last seen none":       {`last_seen_days > 900`, 0},
		"parenthesised":        {`(ram_gb > 100 OR hostname LIKE 'LAPTOP%') AND ram_gb < 16`, 1},
		"quote in literal":     {`hostname = 'it''s'`, 0},
		"injection is literal": {`hostname = 'x''; DROP TABLE devices; --'`, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, total, err := svc.Preview(ctx, tc.rule, store.Page{})
			if err != nil {
				t.Fatalf("Preview(%q): %v", tc.rule, err)
			}
			if total != tc.want {
				t.Errorf("Preview(%q) matched %d devices, want %d", tc.rule, total, tc.want)
			}
		})
	}

	// The table is still there: the injection attempt was a literal.
	if _, err := st.Q().ListGroups(ctx); err != nil {
		t.Fatalf("the database should be intact: %v", err)
	}
}

// One device's software list must not be able to break a rule for everyone:
// a version too long for an integer, and one that is not a dotted number at
// all, both used to be able to fail the whole membership query.
func TestVersionRulesSurviveOddVersions(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	device(t, st, "NORMAL", 8, store.Software{Name: "Google Chrome", Version: "121.0.6167"})
	device(t, st, "HUGE", 8, store.Software{Name: "Google Chrome", Version: "1.99999999999999999999"})
	device(t, st, "BETA", 8, store.Software{Name: "Google Chrome", Version: "122.0-beta"})

	for rule, want := range map[string]int{
		`has_software('Google Chrome', '>=', '120.0.0')`: 1,
		`has_software('Google Chrome', '<', '120.0.0')`:  1,
		`has_software('Google Chrome', '>', '1.5')`:      2,
	} {
		_, total, err := svc.Preview(ctx, rule, store.Page{})
		if err != nil {
			t.Fatalf("Preview(%q): %v", rule, err)
		}
		if total != want {
			t.Errorf("Preview(%q) matched %d, want %d", rule, total, want)
		}
	}
}

func TestBuiltinGroupHoldsEveryActiveDevice(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	device(t, st, "ONE", 8)
	device(t, st, "TWO", 8)

	if _, err := svc.EvaluateAll(ctx); err != nil {
		t.Fatal(err)
	}
	_, total, err := st.Q().ListGroupMembers(ctx, store.BuiltinGroupID, store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("the built-in group should hold both devices, got %d", total)
	}

	g, err := svc.Get(ctx, store.BuiltinGroupID)
	if err != nil {
		t.Fatal(err)
	}
	if g.EvaluatedAt == nil {
		t.Error("evaluating should record when it happened")
	}
}

func TestStaticGroupMembership(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	d := device(t, st, "PINNED", 8)

	g, err := svc.Create(ctx, groups.NewGroup{Name: "Pilot", Kind: store.GroupStatic, Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.AddMember(ctx, g.ID, d.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, total, _ := st.Q().ListGroupMembers(ctx, g.ID, store.Page{}); total != 1 {
		t.Fatalf("want 1 member, got %d", total)
	}

	// A sweep must not touch a static group.
	if _, err := svc.EvaluateAll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, total, _ := st.Q().ListGroupMembers(ctx, g.ID, store.Page{}); total != 1 {
		t.Fatal("evaluating derived groups must leave a static group alone")
	}

	if err := svc.RemoveMember(ctx, g.ID, d.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, total, _ := st.Q().ListGroupMembers(ctx, g.ID, store.Page{}); total != 0 {
		t.Fatal("the member should be gone")
	}
}

func TestDerivedMembershipCannotBeEditedByHand(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	d := device(t, st, "AUTO", 8)

	g, err := svc.Create(ctx, groups.NewGroup{
		Name: "Everything", Kind: store.GroupDynamic, Rule: "ram_gb >= 0", Actor: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.AddMember(ctx, g.ID, d.ID, "test"); err == nil {
		t.Fatal("a dynamic group's membership should not be editable")
	}
	if err := svc.AddMember(ctx, store.BuiltinGroupID, d.ID, "test"); err == nil {
		t.Fatal("the built-in group's membership should not be editable")
	}
}

func TestBuiltinGroupIsProtected(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	if err := svc.Delete(ctx, store.BuiltinGroupID, "test"); err == nil {
		t.Error("the built-in group should not be deletable")
	}
	if _, err := svc.Update(ctx, store.BuiltinGroupID, groups.NewGroup{Name: "Renamed"}); err == nil {
		t.Error("the built-in group should not be renamable")
	}
}

func TestDuplicateNameRejected(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	if _, err := svc.Create(ctx, groups.NewGroup{Name: "Pilot", Kind: store.GroupStatic, Actor: "t"}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.Create(ctx, groups.NewGroup{Name: "pilot", Kind: store.GroupStatic, Actor: "t"})
	if err == nil {
		t.Fatal("names should be unique regardless of case")
	}
}

func TestUpdateRuleReevaluates(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	device(t, st, "BIG", 32)
	device(t, st, "SMALL", 4)

	g, err := svc.Create(ctx, groups.NewGroup{
		Name: "Fleet", Kind: store.GroupDynamic, Rule: "ram_gb >= 16", Actor: "t",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, total, _ := st.Q().ListGroupMembers(ctx, g.ID, store.Page{}); total != 1 {
		t.Fatalf("want 1 member to start, got %d", total)
	}

	if _, err := svc.Update(ctx, g.ID, groups.NewGroup{
		Name: "Fleet", Kind: store.GroupDynamic, Rule: "ram_gb >= 1", Actor: "t",
	}); err != nil {
		t.Fatal(err)
	}
	if _, total, _ := st.Q().ListGroupMembers(ctx, g.ID, store.Page{}); total != 2 {
		t.Fatalf("a changed rule should re-evaluate immediately, got %d", total)
	}
}

func TestEffectiveItemsExcludeWins(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	d := device(t, st, "TARGET", 8)

	inc, err := svc.Create(ctx, groups.NewGroup{Name: "Included", Kind: store.GroupStatic, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	exc, err := svc.Create(ctx, groups.NewGroup{Name: "Excluded", Kind: store.GroupStatic, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []store.Group{inc, exc} {
		if err := svc.AddMember(ctx, g.ID, d.ID, "t"); err != nil {
			t.Fatal(err)
		}
	}

	item := uuid.Must(uuid.NewV7())
	assign := func(groupID uuid.UUID, mode string) {
		t.Helper()
		if _, err := st.Q().CreateAssignment(ctx, store.Assignment{
			ID: uuid.Must(uuid.NewV7()), ItemKind: "script", ItemID: item,
			GroupID: groupID, Mode: mode, CreatedAt: time.Now(), CreatedBy: "t",
		}); err != nil {
			t.Fatal(err)
		}
	}

	assign(inc.ID, store.ModeInclude)
	items, err := st.Q().EffectiveItems(ctx, d.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != item {
		t.Fatalf("want the item included, got %v", items)
	}

	assign(exc.ID, store.ModeExclude)
	items, err = st.Q().EffectiveItems(ctx, d.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("exclude must win, got %v", items)
	}
}

func TestItemStatusRollup(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	a := device(t, st, "A", 8)
	b := device(t, st, "B", 8)
	item := uuid.Must(uuid.NewV7())

	for _, s := range []struct {
		dev    uuid.UUID
		status string
	}{{a.ID, store.ItemSucceeded}, {b.ID, store.ItemFailed}} {
		if err := st.Q().SetItemStatus(ctx, store.ItemStatus{
			DeviceID: s.dev, ItemKind: "script", ItemID: item,
			Status: s.status, UpdatedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	rollup, err := st.Q().ItemStatusRollup(ctx, "script", item, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if rollup[store.ItemSucceeded] != 1 || rollup[store.ItemFailed] != 1 {
		t.Fatalf("rollup = %v", rollup)
	}

	failed, total, err := st.Q().ListItemStatus(ctx, "script", item, store.ItemFailed, store.Page{}, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || failed[0].Hostname != "B" {
		t.Fatalf("drill-down = %v (total %d)", failed, total)
	}

	// Reporting again replaces the row rather than adding one.
	if err := st.Q().SetItemStatus(ctx, store.ItemStatus{
		DeviceID: b.ID, ItemKind: "script", ItemID: item,
		Status: store.ItemSucceeded, Detail: "retried", UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	rollup, err = st.Q().ItemStatusRollup(ctx, "script", item, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if rollup[store.ItemSucceeded] != 2 || rollup[store.ItemFailed] != 0 {
		t.Fatalf("a later report should replace the earlier one, got %v", rollup)
	}
}
