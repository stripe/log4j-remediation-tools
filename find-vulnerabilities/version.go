package main

import (
	"log"

	"github.com/hashicorp/go-version"
)

var (
	version2     = version.Must(version.NewVersion("2.0.0"))
	flagVersion  = version.Must(version.NewVersion("2.10.0"))
	fixedVersion = version.Must(version.NewVersion("2.16.0"))
)

func parseVersion(ver string) (*version.Version, error) {
	// Add any custom version parsing logic here
	return version.NewVersion(ver)
}

func isPatchedVersion(ver *version.Version) bool {
	// If the version is newer than the fixed version, we're good.
	if ver.GreaterThanOrEqual(fixedVersion) {
		if *verbose {
			log.Printf("not vulnerable: version newer")
		}
		return true
	}

	// Add special cases here
	switch ver.Original() {
	// e.g.  case "my version":
	//	return true
	}

	return false
}
