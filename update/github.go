package update

import (
	"context"
	"fmt"
	"github.com/blang/semver"
	"github.com/google/go-github/github"
)

type GitHub struct {
	CurrentVersion     string // Currently running version.
	GithubOwner        string // The owner of the repo like "pcdummy"
	GithubRepo         string // The repository like "go-githubupdate"
	Certificate        string
	latestReleasesResp *github.RepositoryRelease
}

func (u *GitHub) getCert() string {
	return u.Certificate
}

func (u *GitHub) CheckUpdateAvailable() (string, error) {
	client := github.NewClient(nil)

	ctx := context.Background()
	release, _, err := client.Repositories.GetLatestRelease(ctx, u.GithubOwner, u.GithubRepo)
	if err != nil {
		return "", err
	}

	u.latestReleasesResp = release

	var updateVersion string
	fmt.Sscanf(*u.latestReleasesResp.TagName, "v%s", &updateVersion)
	current, err := semver.Make(u.CurrentVersion)
	update, err := semver.Make(updateVersion)
	if current.LT(update) {
		return *u.latestReleasesResp.TagName, nil
	}

	return "", nil
}
func (u *GitHub) getAssets() (string, string, string, error) {
	reqFilename := u.GithubRepo + "-" + platform
	var binaryAsset, checksumAsset, signatureAsset github.ReleaseAsset
	for _, asset := range u.latestReleasesResp.Assets {
		if *asset.Name == reqFilename {
			binaryAsset = asset
		} else if *asset.Name == reqFilename+".sha256" {
			checksumAsset = asset
		} else if *asset.Name == reqFilename+".sig" {
			signatureAsset = asset
		}
	}

	if binaryAsset.Name == nil {
		return "", "", "", ErrorNoBinary
	} else if checksumAsset.Name == nil {
		return "", "", "", ErrorNoCheckSum
	} else if signatureAsset.Name == nil {
		return "", "", "", ErrorNoSignature
	}
	return *binaryAsset.BrowserDownloadURL, *checksumAsset.BrowserDownloadURL, *signatureAsset.BrowserDownloadURL, nil
}
