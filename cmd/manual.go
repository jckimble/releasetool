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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

// releaseCmd represents the release command
var releaseManualCmd = &cobra.Command{
	Use:   "manual",
	Short: "Output Release Files",
	Run:   publishFileRelease,
	Args:  validateFileRelease,
}
var url string

func init() {
	RootCmd.AddCommand(releaseManualCmd)
	releaseManualCmd.Flags().StringVarP(&url, "url", "u", "", "Base URL for Updating")
	releaseManualCmd.Flags().StringVarP(&tag, "tag", "t", "", "Git tag to create release from (required)")
	releaseManualCmd.Flags().StringVarP(&key, "privatekey", "k", "", "PrivateKey Path (required if $KEY not set)")
}

func validateFileRelease(cmd *cobra.Command, args []string) error {
	if tag == "" {
		return fmt.Errorf("--tag flag must be set")
	}
	if key == "" && os.Getenv("KEY") == "" {
		return fmt.Errorf("--privatekey or $KEY env must be set")
	}
	return nil
}

func publishFileRelease(cmd *cobra.Command, args []string) {
	client := NewManualClient("download")
	err := client.CreateRelease()
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
	client.WriteJson()
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

type Manual struct {
	Path string
	URL  string
	Json VersionJson
}

func NewManualClient(path string) *Manual {
	return &Manual{
		Path: path,
		Json: VersionJson{
			Version: tag,
		},
	}
}
func (g *Manual) CreateRelease() error {
	os.Mkdir(g.Path, 0755)
	return nil
}
func (g *Manual) UploadAsset(filename string, data []byte) error {
	u := fmt.Sprintf("%s/%s", g.Path, filename)
	err := ioutil.WriteFile(u, data, 0644)
	if err != nil {
		return err
	}
	if strings.HasSuffix(filename, ".sig") || strings.HasSuffix(filename, ".sha256") || filename == "version.json" {
		return nil
	}
	r, _ := regexp.Compile("([a-zA-Z0-9]+-[a-zA-Z0-9]+)$")
	if err != nil {
		fmt.Printf("%s\n", err)
	}
	g.Json.Assets = append(g.Json.Assets, Assets{
		Platform:  r.FindString(filename),
		Binary:    fmt.Sprintf("%s/%s", url, filename),
		Checksum:  fmt.Sprintf("%s/%s.sha256", url, filename),
		Signature: fmt.Sprintf("%s/%s.sig", url, filename),
	})
	return err
}
func (g *Manual) WriteJson() error {
	data, err := json.Marshal(g.Json)
	if err != nil {
		return err
	}
	return g.UploadAsset("version.json", data)
}
