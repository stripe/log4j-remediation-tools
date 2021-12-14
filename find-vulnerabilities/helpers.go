package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
)

func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "error"
	}
	defer f.Close()

	return hashFsFile(f)
}

func hashFsFile(f fs.File) string {
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "error"
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

func fileExists(path string) bool {
	info, err := os.Lstat(path)

	switch {
	case os.IsNotExist(err):
		// path does not exist
		return false
	case err != nil:
		// return true since error is not of type IsNotExist
		return true
	default:
		// return true only if this is a file
		return info.Mode().IsRegular()
	}
}
