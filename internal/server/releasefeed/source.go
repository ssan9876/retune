// Package releasefeed watches for new Retune releases, verifies their signed
// manifests, imports their agent builds, and rolls those builds out to the
// fleet in stages when an administrator has asked for that.
//
// Nothing a release feed hands over is trusted until release.json has been
// verified against AGENT_RELEASE_KEYS: the feed's list of releases is only a
// list of places to look, and every file downloaded from one is checked
// against a hash in a manifest the release key signed.
package releasefeed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Candidate is a release a feed lists: not verified, just a place to look.
type Candidate struct {
	Version     string
	Prerelease  bool
	Draft       bool
	PublishedAt time.Time
	// Assets maps each published file's name to where to download it.
	Assets map[string]string
}

// Source lists releases and downloads their files.
type Source interface {
	List(ctx context.Context) ([]Candidate, error)
	// Open downloads one file. The caller limits how much it reads.
	Open(ctx context.Context, url string) (io.ReadCloser, error)
}

// GitHub reads the GitHub releases API, or anything that serves the same JSON.
type GitHub struct {
	URL    string
	Client *http.Client
}

func (g GitHub) client() *http.Client {
	if g.Client != nil {
		return g.Client
	}
	return &http.Client{Timeout: 10 * time.Minute}
}

// githubRelease is the part of the GitHub API's release object read here.
type githubRelease struct {
	TagName     string    `json:"tag_name"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// maxListBytes caps the release list: twenty releases of a few dozen assets
// each is well under this.
const maxListBytes = 4 << 20

// List fetches the releases.
func (g GitHub) List(ctx context.Context) ([]Candidate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "retune-server")
	resp, err := g.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release feed %s answered %s", g.URL, resp.Status)
	}
	var releases []githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxListBytes)).Decode(&releases); err != nil {
		return nil, fmt.Errorf("release feed %s: %w", g.URL, err)
	}
	out := make([]Candidate, 0, len(releases))
	for _, r := range releases {
		c := Candidate{
			Version: strings.TrimPrefix(r.TagName, "v"), Prerelease: r.Prerelease, Draft: r.Draft,
			PublishedAt: r.PublishedAt, Assets: map[string]string{},
		}
		for _, a := range r.Assets {
			c.Assets[a.Name] = a.URL
		}
		out = append(out, c)
	}
	return out, nil
}

// Open downloads one file.
func (g GitHub) Open(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "retune-server")
	resp, err := g.client().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("download %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

// errTooLarge is a download that ran past its limit.
var errTooLarge = errors.New("download is larger than expected")

// readAll downloads a small file whole, refusing one larger than max.
func readAll(ctx context.Context, src Source, url string, max int64) ([]byte, error) {
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
		return nil, fmt.Errorf("%s: %w", url, errTooLarge)
	}
	return b, nil
}
