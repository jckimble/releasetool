package update

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"runtime"
	"strings"

	"github.com/inconshreveable/go-update"
)

const (
	platform = runtime.GOOS + "-" + runtime.GOARCH
)

var (
	ErrorNoBinary    = errors.New("no binary for the update found")
	ErrorNoCheckSum  = errors.New("no checksum for the update found")
	ErrorNoSignature = errors.New("no signature for the update found")
)

type UpdaterService interface {
	CheckUpdateAvailable() (string, error)
	GetAssets() (string, string, string, error)
	GetCert() string
}

func Update(u UpdaterService) error {
	binary, checksum, signature, err := u.GetAssets()
	if err != nil {
		return err
	}
	resp, err := http.Get(binary)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	checksumParsed, err := parseChecksum(checksum)
	if err != nil {
		return err
	}
	opts := update.Options{
		Checksum: checksumParsed,
		Hash:     crypto.SHA256,
	}
	cert := u.GetCert()
	if cert != "" {
		opts.PublicKey, err = getPublicKey(cert)
		if err != nil {
			return err
		}
		opts.Signature, err = getSignature(signature)
		if err != nil {
			return err
		}
		opts.Verifier = update.NewRSAVerifier()
	}
	err = update.Apply(resp.Body, opts)
	if err != nil {
		return err
	}
	return nil
}

func getPublicKey(key string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(key))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert.PublicKey.(*rsa.PublicKey), nil

}

func getSignature(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func parseChecksum(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	sha256, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.Trim(string(sha256), " \n"))
}
