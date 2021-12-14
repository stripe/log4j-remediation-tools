package main

import (
	"archive/zip"
	"bufio"
	"log"
	"strings"
)

func versionFromJARArchive(r *zip.Reader) string {
	if ver := versionFromJARArchiveFingerprint(r); ver != "unknown" {
		return ver
	}
	if ver := versionFromJARArchiveMeta(r); ver != "unknown" {
		return ver
	}

	return "unknown"
}

func versionFromJARArchiveFingerprint(r *zip.Reader) string {
	for _, fp := range log4jFingerprints {
		f, err := r.Open(fp.file)
		if err != nil {
			continue
		}
		defer f.Close()

		hash := hashFsFile(f)
		if hash == fp.sha256 {
			if *verbose {
				log.Printf("found log4j version %q by fingerprint", fp.version)
			}
			return fp.version
		}
	}

	return "unknown"
}

func versionFromJARArchiveMeta(r *zip.Reader) string {
	f, err := r.Open("META-INF/MANIFEST.MF")
	if err != nil {
		return "unknown"
	}
	defer f.Close()

	metadata := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ": ", 2)
		if len(parts) == 2 {
			metadata[parts[0]] = parts[1]
		} else {
			// Noisy
			//log.Printf("invalid manifest line: %q", scanner.Text())
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("error reading manifest file: %w", err)
		return "unknown"
	}

	candidates := []string{"Implementation-Version", "Bundle-Version"}
	for _, candidate := range candidates {
		if s, ok := metadata[candidate]; ok {
			return s
		}
	}

	return "unknown"
}
