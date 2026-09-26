package serverupdate

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"retune/internal/server/releasefeed"
)

// The release files an update reads, and how large each may be.
const (
	ManifestFile  = "release.json"
	SignatureFile = "release.json.sig"
	maxManifest   = 1 << 20
	maxSignature  = 16 << 10
)

// FeedFetcher reads a release's manifest from the release feed - the GitHub
// releases API or a mirror of it - the same place the server found it.
type FeedFetcher struct {
	Source releasefeed.Source
}

// Fetch downloads release.json and its signature for one version.
func (f FeedFetcher) Fetch(ctx context.Context, version string) ([]byte, []byte, error) {
	c, err := FindCandidate(ctx, f.Source, version)
	if err != nil {
		return nil, nil, err
	}
	raw, err := download(ctx, f.Source, c.Assets[ManifestFile], maxManifest)
	if err != nil {
		return nil, nil, err
	}
	sig, err := download(ctx, f.Source, c.Assets[SignatureFile], maxSignature)
	if err != nil {
		return nil, nil, err
	}
	return raw, sig, nil
}

// FindCandidate finds one version among the releases a feed lists.
func FindCandidate(ctx context.Context, src releasefeed.Source, version string) (releasefeed.Candidate, error) {
	want := strings.TrimPrefix(version, "v")
	list, err := src.List(ctx)
	if err != nil {
		return releasefeed.Candidate{}, err
	}
	for _, c := range list {
		if c.Version == want {
			if c.Assets[ManifestFile] == "" || c.Assets[SignatureFile] == "" {
				return releasefeed.Candidate{}, fmt.Errorf("release %s publishes no signed %s", want, ManifestFile)
			}
			return c, nil
		}
	}
	return releasefeed.Candidate{}, fmt.Errorf("the release feed does not list %s", want)
}

func download(ctx context.Context, src releasefeed.Source, url string, max int64) ([]byte, error) {
	body, err := src.Open(ctx, url)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	b, err := io.ReadAll(io.LimitReader(body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is larger than expected", url)
	}
	return b, nil
}

// DirFetcher reads a release's manifest from a directory the server staged
// it in: DIR/<version>/release.json. It is only a way of getting the bytes -
// the Updater verifies them against its own keys all the same.
type DirFetcher struct {
	Dir string
}

// Fetch reads release.json and its signature from the version's directory.
func (d DirFetcher) Fetch(_ context.Context, version string) ([]byte, []byte, error) {
	dir := filepath.Join(d.Dir, safe(strings.TrimPrefix(version, "v")))
	raw, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return nil, nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, SignatureFile))
	if err != nil {
		return nil, nil, err
	}
	return raw, sig, nil
}
