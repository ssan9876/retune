package policy

// QuoteForTest exposes quote to the external tests.
func QuoteForTest(s string) string { return quote(s) }
