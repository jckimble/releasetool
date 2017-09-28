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
	"fmt"

	"github.com/jckimble/releasetool/update"
	"github.com/spf13/cobra"
	"log"
)

var Version = "v0.0.0"

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Check for update",
	Run:   runUpdate,
}

func init() {
	RootCmd.AddCommand(updateCmd)
}
func runUpdate(cmd *cobra.Command, args []string) {
	var version string
	fmt.Sscanf(Version, "v%s", &version)
	u := &update.GitHub{
		CurrentVersion: version,
		GithubOwner:    "jckimble",
		GithubRepo:     "releasetool",
		Certificate: `-----BEGIN CERTIFICATE-----
MIICszCCAZugAwIBAgIRALKJ5NTFlyCJo8xHkKpZIT8wDQYJKoZIhvcNAQELBQAw
CzEJMAcGA1UEChMAMB4XDTE3MDkyODIzMDkwOFoXDTI3MDkyNjIzMDkwOFowCzEJ
MAcGA1UEChMAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyb2Me0+2
q3M6JaUcYcA8TfnqP/2WjXu7X6L2a30Li7bd8tX4r2I5Vu21+nxvRnutrXclDoM4
4d4eYI+/FjemBVdPdH5GIHPjNrObeBkZL1n/TC5EZLO0NAi67uVOpi/OS7K9Wxe/
OlZJqmXeMO6Tk2UvXZc3W3YcpJX5InicDGI0KpBBmXpaI7049gIW2Rwl81deWPWc
8rI+lpgGK7Hzbky/2gWtBixA2ikvVoiPxW+u2yfiNtcU7VT3gAcdggf3eCG82oA6
6E3XPjptjjHoTRGj2NSn+RXBmObx/PYLBykf73bNu1KG52LOA482KDm0TGXRjWrL
tliwPHmMfDo18wIDAQABoxIwEDAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQEL
BQADggEBAG61Dk4zNTM8zIUYKUkjGyZGvcXwzK2k0ANu6jRf+edUX81y/lDEYmRC
OROdDGrX+XEPo04HujSh+uNIQ+w/JX/2lnjjZ36EsqwulHZpbLGUpryixq4wjz2Y
cyGwlPWhizJcH48ArexFFpHUEEj27xbKWSOhf+98lvaDAXHz2P6DLE4c3X3IOX88
GfuVW0GvUBBv4/7Lgh9zEaU3Eq/hS8a+da4kDmzKgScg4yoPUb7QZ++I8f4FN7CY
eLkHijv8HZswkPjZ1jQ6Vqq7mbGtFqX3oP5eOjRL5BGGTC3GGbuaS+RBWssLpi3y
RRCeltRpz0tXNoJDvr1hiJoW1+TSBX0=
-----END CERTIFICATE-----`,
	}
	available, err := u.CheckUpdateAvailable()
	if err != nil {
		log.Printf("Unable to check Update: %s\n", err)
	}
	if available != "" {
		log.Printf("Version %s available\n", available)
		err := update.Update(u)
		if err != nil {
			log.Printf("Unable to Update: %s\n", err)
		}
	} else {
		log.Println("ReleaseTool is current Version")
	}
}
