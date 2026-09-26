package store

// Exported for the upgrade tests in package store_test, which need storetest
// and so cannot live in this package.
var (
	MigrateTo       = migrateTo
	MigrateDown     = migrateDown
	SchemaVersion   = schemaVersion
	LatestMigration = latestMigration
)
