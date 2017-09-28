// Copyright © 2017 James Kimble
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"mime"
	"os"
	"path/filepath"

	"github.com/google/go-github/github"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

// releaseCmd represents the release command
var releaseCmd = &cobra.Command{
	Use:   "release",
	Short: "Publish release",
	Run:   publishRelease,
	Args:  validateRelease,
}

var user, repo, tag, name, description, token, key string
var prerelease, draft bool

func init() {
	RootCmd.AddCommand(releaseCmd)
	releaseCmd.Flags().StringVarP(&user, "user", "u", "", "Github user (required if $GITHUB_USER not set)")
	releaseCmd.Flags().StringVarP(&repo, "repo", "r", "", "Github repo (required if $GITHUB_REPO not set)")
	releaseCmd.Flags().StringVarP(&tag, "tag", "t", "", "Git tag to create release from (required)")
	releaseCmd.Flags().StringVarP(&name, "name", "n", "", "Name of release(defaults to tag)")
	releaseCmd.Flags().StringVarP(&description, "description", "d", "", "Description of release(defaults to tag)")
	releaseCmd.Flags().StringVar(&token, "token", "", "Github token (required if $GITHUB_TOKEN not set)")
	releaseCmd.Flags().StringVarP(&key, "privatekey", "k", "", "PrivateKey Path (required if $KEY not set)")
	releaseCmd.Flags().BoolVarP(&prerelease, "pre-release", "p", false, "Release is a pre-release")
	releaseCmd.Flags().BoolVar(&draft, "draft", false, "Release is a draft")
}

func validateRelease(cmd *cobra.Command, args []string) error {
	if user == "" {
		user = os.Getenv("GITHUB_USER")
		if user == "" {
			return fmt.Errorf("--user flag or $GITHUB_USER env must be set")
		}
	}
	if repo == "" {
		repo = os.Getenv("GITHUB_REPO")
		if repo == "" {
			return fmt.Errorf("--repo flag or $GITHUB_REPO env must be set")
		}
	}
	if tag == "" {
		return fmt.Errorf("--tag flag must be set")
	}
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
		if token == "" {
			return fmt.Errorf("--token flag or $GITHUB_TOKEN env must be set")
		}
	}
	if key == "" && os.Getenv("KEY") == "" {
		return fmt.Errorf("--privatekey or $KEY env must be set")
	}
	return nil
}

func publishRelease(cmd *cobra.Command, args []string) {
	if name == "" {
		name = tag
	}
	req := &github.RepositoryRelease{
		Name:       github.String(name),
		TagName:    github.String(tag),
		Prerelease: github.Bool(prerelease),
		Draft:      github.Bool(draft),
	}
	client := NewGitHubClient(user, repo, token)
	err := client.CreateRelease(req)
	if err != nil {
		log.Fatalf("Unable to create release: %s\n", err)
	}
	for _, file := range args {
		rng := rand.Reader
		binary, err := ioutil.ReadFile(file)
		if err != nil {
			log.Fatalf("%s\n", err)
		}
		keyData, err := getKey()
		if err != nil {
			log.Fatalf("%s\n", err)
		}
		block, _ := pem.Decode(keyData)
		rsaPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("%s\n", err)
		}
		hashed := sha256.Sum256(binary)
		signature, err := rsa.SignPKCS1v15(rng, rsaPrivateKey.(*rsa.PrivateKey), crypto.SHA256, hashed[:])
		if err != nil {
			log.Fatalf("%s\n", err)
		}
		sha256 := fmt.Sprintf("%x", hashed)
		sigfile := fmt.Sprintf("%s.sig", file)
		sha256file := fmt.Sprintf("%s.sha256", file)
		if err = client.UploadAsset(sigfile, signature); err != nil {
			log.Fatalf("Error Uploading Release File: %s\n", err)
		}
		if err = client.UploadAsset(sha256file, []byte(sha256)); err != nil {
			log.Fatalf("Error Uploading Release File: %s\n", err)
		}
		if err = client.UploadAsset(file, binary); err != nil {
			log.Fatalf("Error Uploading Release File: %s\n", err)
		}
	}
}

func getKey() ([]byte, error) {
	if key == "" {
		key = os.Getenv("KEY")
		if key == "" {
			return nil, fmt.Errorf("Key is not set")
		}
		keyData, _ := base64.URLEncoding.DecodeString(key)
		return keyData, nil
	} else {
		return ioutil.ReadFile(key)
	}
}

type GitHub struct {
	client    *github.Client
	user      string
	repo      string
	ReleaseId int
}

func NewGitHubClient(user, repo, token string) *GitHub {
	ts := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: token,
	})
	tc := oauth2.NewClient(oauth2.NoContext, ts)
	return &GitHub{
		client: github.NewClient(tc),
		user:   user,
		repo:   repo,
	}
}
func (g *GitHub) CreateRelease(release *github.RepositoryRelease) error {
	new, _, err := g.client.Repositories.CreateRelease(context.Background(), g.user, g.repo, release)
	if err != nil {
		return err
	}
	g.ReleaseId = *new.ID
	return nil
}
func (g *GitHub) UploadAsset(filename string, data []byte) error {
	u := fmt.Sprintf("repos/%s/%s/releases/%d/assets", g.user, g.repo, g.ReleaseId)
	mediaType := mime.TypeByExtension(filepath.Ext(filename))
	reader := bytes.NewReader(data)
	_, err := g.client.NewUploadRequest(u, reader, int64(len(data)), mediaType)
	if err != nil {
		return err
	}
	return nil
}
