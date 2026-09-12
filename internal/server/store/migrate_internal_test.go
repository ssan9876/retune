package store

import "testing"

func TestMigrateURL(t *testing.T) {
	cases := map[string]string{
		"postgres://u:p@h/db":   "pgx5://u:p@h/db",
		"postgresql://u:p@h/db": "pgx5://u:p@h/db",
		"pgx5://u:p@h/db":       "pgx5://u:p@h/db",
	}
	for in, want := range cases {
		if got := migrateURL(in); got != want {
			t.Errorf("migrateURL(%q) = %q, want %q", in, got, want)
		}
	}
}
