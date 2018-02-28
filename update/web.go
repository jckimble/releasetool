package update

import (
	"encoding/json"
	"fmt"
	"github.com/blang/semver"
	"net/http"
	"time"
)

type WebDirectory struct {
	CurrentVersion string // Currently running version.
	Url            string
	Certificate    string
	VersionJson    *VersionJson
}

type VersionJson struct {
	Version string
	Assets  []Assets
}
type Assets struct {
	Platform  string
	Binary    string
	Checksum  string
	Signature string
}

func (u *WebDirectory) GetCert() string {
	return u.Certificate
}

func (u *WebDirectory) CheckUpdateAvailable() (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	r, err := client.Get(u.Url + "version.json")
	if err != nil {
		return "", fmt.Errorf("Unable to get version.json: %s\n", err)
	}
	defer r.Body.Close()
	u.VersionJson = new(VersionJson)
	err = json.NewDecoder(r.Body).Decode(u.VersionJson)
	if err != nil {
		return "", err
	}
	var updateVersion string
	fmt.Sscanf(u.VersionJson.Version, "v%s", &updateVersion)
	current, err := semver.Make(u.CurrentVersion)
	update, err := semver.Make(updateVersion)
	if current.LT(update) {
		return u.VersionJson.Version, nil
	}
	return "", nil
}
func (u *WebDirectory) GetAssets() (string, string, string, error) {
	for _, asset := range u.VersionJson.Assets {
		if asset.Platform == platform {
			if asset.Binary == "" {
				return "", "", "", ErrorNoBinary
			} else if asset.Checksum == "" {
				return "", "", "", ErrorNoCheckSum
			} else if asset.Signature == "" {
				return "", "", "", ErrorNoSignature
			}
			return asset.Binary, asset.Checksum, asset.Signature, nil
		}
	}
	return "", "", "", ErrorNoBinary
}
