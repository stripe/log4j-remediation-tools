// Searches the system for artifacts related to log4j and prints them to stdout

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/hashicorp/go-version"
	"github.com/shirou/gopsutil/process"
)

var verbose = flag.Bool("verbose", false, "be more verbose")

func main() {
	flag.Parse()
	log.SetOutput(os.Stderr)
	defer log.Printf("done")

	if syscall.Geteuid() != 0 {
		log.Fatal("this tool must be run as root")
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	selfHash := hashFile(os.Args[0])

	procs, err := process.Processes()
	if err != nil {
		log.Fatalf("error getting processes: %+v", err)
	}

	report := makeReport(procs)

	// Sort by the PID
	sort.SliceStable(report, func(i, j int) bool {
		return report[i].PID < report[j].PID
	})

	// Sort all versions
	for _, entry := range report {
		sort.SliceStable(entry.JARs, func(i, j int) bool {
			j1 := entry.JARs[i]
			j2 := entry.JARs[j]

			// If we have both objects, compare them
			if j1.VersionObj != nil && j2.VersionObj != nil {
				return j1.VersionObj.LessThan(j2.VersionObj)
			}

			// Things with valid versions sort before things
			// without versions.
			if j1.VersionObj == nil && j2.VersionObj != nil {
				return true
			} else if j1.VersionObj != nil && j2.VersionObj == nil {
				return false
			}

			// We have no version objects at all; fall back to just
			// comparing the raw strings.
			return j1.VersionStr < j2.VersionStr
		})
	}

	// Columns:
	// 1. Hostname
	// 2. Tool (lite vs full)
	// 3. Tool sha
	// 4. Pid
	// 5. Java binary location
	// 6. Java version & release (e.g. adoptopenjdk-1.8.0u181)
	// 7. Value of log4j2.formatMsgNoLookups
	// 8. Value of com.sun.jndi.ldap.object.trustURLCodebase
	// 9. Value of com.sun.jndi.rmi.object.trustURLCodebase
	// 10. Value of com.sun.jndi.cosnaming.object.trustURLCodebase
	// 11. Is using log4j?
	// 12. Oldest Log4j version found
	// 13. Summary:  vulnerable: yes/no/maybe
	// 14. Oldest vulnerable log4j version found (i.e. >= 2.0.0)

	w := csv.NewWriter(os.Stdout)
	defer w.Flush()

	w.Write([]string{
		"hostname", "tool", "tool_sha", "pid", "java_bin_location",
		"java_version", "prop1", "prop2", "prop3", "prop4",
		"using_log4j", "oldest_log4j_version", "vulnerable",
		"oldest_vulnerable_log4j_version",
	})

	for _, entry := range report {
		binaryLocation := "unknown"
		if s, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", entry.PID)); err == nil {
			binaryLocation = s
		}

		fields := []string{
			hostname,
			"lite",
			selfHash,
			fmt.Sprint(entry.PID),
			binaryLocation,
			entry.SystemProperties["java.version"],
			entry.SystemProperties["log4j2.formatMsgNoLookups"],
			entry.SystemProperties["com.sun.jndi.ldap.object.trustURLCodebase"],
			entry.SystemProperties["com.sun.jndi.rmi.object.trustURLCodebase"],
			entry.SystemProperties["com.sun.jndi.cosnaming.object.trustURLCodebase"],
			fmt.Sprint(entry.UsingLog4j()),
			"set-below", // oldest_log4j_version
			"set-below", // vulnerable
			"set-below", // oldest_vulnerable_log4j_version
		}

		// If we have any JAR files, then we're using Log4j
		var (
			oldestVersion       = "unknown"
			oldestVulnerableStr = "unknown"
			oldestVulnerableObj *version.Version
		)
		if len(entry.JARs) > 0 {
			oldestVersion = entry.JARs[0].VersionStr

			// Find the oldest version of log4j that's vulnerable.
			// Note that this list is sorted, so we break at the
			// loop when we've found one that matches.
			for _, jar := range entry.JARs {
				if jar.VersionObj == nil {
					log.Println("VersionObj == nil")
					continue
				}

				// If we find a version that's before version
				// 2, or after the fixed version, set the
				// "oldest vulnerable" option to the empty
				// string, since if we find nothing else this
				// isn't vulnerable.
				if jar.VersionObj.LessThan(version2) {
					oldestVulnerableStr = ""
				} else if jar.VersionObj.GreaterThanOrEqual(fixedVersion) {
					oldestVulnerableStr = ""
				}

				// The actual check for "is within the vulnerable range"
				if jar.VersionObj.GreaterThanOrEqual(version2) && jar.VersionObj.LessThan(fixedVersion) {
					oldestVulnerableStr = jar.VersionStr
					oldestVulnerableObj = jar.VersionObj
				}
			}
		}
		fields[11] = oldestVersion
		fields[12] = checkVulnerable(entry, oldestVulnerableObj)
		fields[13] = oldestVulnerableStr

		w.Write(fields)
	}
}

func checkVulnerable(entry ReportEntry, oldestVersion *version.Version) string {
	if !entry.UsingLog4j() {
		return "no"
	}

	// If we have a version that can't be parsed, then we're going to
	// report as "maybe vulnerable".
	if oldestVersion == nil {
		return "maybe"
	}

	// If the version is newer than the fixed version, we're good.
	if isPatchedVersion(oldestVersion) {
		if *verbose {
			log.Printf("not vulnerable: version patched")
		}
		return "no"
	}

	// If we're older than the version that allows disabling message
	// lookups, then there's no way to make this safe, so we're vulnerable.
	if oldestVersion.LessThan(flagVersion) {
		if *verbose {
			log.Printf("vulnerable: lookups can't be disabled on this version")
		}
		return "yes"
	}

	// If the system property to disable message lookups is set, then we're
	// not vulnerable.
	if entry.SystemProperties["log4j2.formatMsgNoLookups"] == "true" {
		if *verbose {
			log.Printf("not vulnerable: formatMsgNoLookups")
		}
		return "no"
	}

	// If the process has the environment variable to disable lookups set, it's also not vulnerable.
	if entry.Environ["LOG4J_FORMAT_MSG_NO_LOOKUPS"] == "true" {
		if *verbose {
			log.Printf("not vulnerable: LOG4J_FORMAT_MSG_NO_LOOKUPS")
		}
		return "no"
	}

	// If we get here, we're vulnerable
	return "yes"
}

func makeReport(procs []*process.Process) (ret []ReportEntry) {
	for _, proc := range procs {
		name, err := proc.Name()
		if err != nil {
			log.Printf("error getting name for process pid=%d", proc.Pid)
			name = "unknown"
		}

		processPath := "unknown"
		if s, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", proc.Pid)); err == nil {
			processPath = s
		}

		if processPath == "unknown" {
			// probably kernel process; skip
			continue
		} else if name == "unknown" {
			// check; don't want to miss this if it's important
		} else if strings.Contains(name, "java") {
			// check
		} else if strings.Contains(processPath, "java") {
			// check
		} else if strings.Contains(processPath, "/jdk/") || strings.Contains(processPath, "/jre/") || strings.Contains(processPath, "/jvm/") {
			// check
		} else {
			// probably not java
			continue
		}

		entry := ReportEntry{
			PID:              proc.Pid,
			ProcName:         name,
			Environ:          make(map[string]string),
			SystemProperties: make(map[string]string),
		}
		if props, err := getSysprops(proc); err == nil {
			//log.Printf("sysprops[%d] = %+v", proc.Pid, props)
			entry.SystemProperties = props
		} else {
			if err := checkCommandline(proc, &entry); err != nil {
				log.Printf("%v", err)
			}
		}
		if err := checkOpenFiles(proc, &entry); err != nil {
			log.Printf("%v", err)
		}
		if env, err := proc.Environ(); err == nil {
			for _, s := range env {
				parts := strings.SplitN(s, "=", 2)
				if len(parts) == 2 {
					entry.Environ[parts[0]] = parts[1]
				}
			}
		}
		ret = append(ret, entry)
	}

	return
}

func checkOpenFiles(proc *process.Process, entry *ReportEntry) error {
	files, err := proc.OpenFiles()
	if err != nil {
		return fmt.Errorf("error getting open files for process %q (pid: %d): %w", entry.ProcName, proc.Pid, err)
	}

	for _, file := range files {
		if strings.Contains(file.Path, "log4j") {
			path := pathForFile(proc, file)

			versionStr := "unknown"
			versionObj := (*version.Version)(nil)
			zr, err := zip.OpenReader(path)
			if err == nil {
				versionStr = versionFromJARArchive(&zr.Reader)
				zr.Close()

				if vo, err := parseVersion(versionStr); err == nil {
					versionObj = vo
				}
			} else if *verbose {
				log.Printf("could not open file %q: %v", path, err)
			}

			hash := hashFile(path)
			entry.JARs = append(entry.JARs, JAREntry{
				Path:       file.Path,
				VersionStr: versionStr,
				VersionObj: versionObj,
				SHA256:     hash,
			})
		}

		if strings.HasSuffix(strings.ToLower(file.Path), ".jar") {
			if err := checkJarFile(proc, entry, file); err != nil {
				return fmt.Errorf("error checking JAR file %q for process %q (pid: %d): %w", file.Path, entry.ProcName, proc.Pid, err)
			}
		}
	}

	return nil
}

func checkCommandline(proc *process.Process, entry *ReportEntry) error {
	cmdline, err := proc.CmdlineSlice()
	if err != nil {
		return fmt.Errorf("error getting command line for process %q (pid: %d): %w", entry.ProcName, proc.Pid, err)
	}

	for _, part := range cmdline {
		if strings.HasPrefix(part, "-D") {
			parts := strings.SplitN(part[2:], "=", 2)
			if len(parts) == 2 {
				entry.SystemProperties[parts[0]] = parts[1]
			}
		}
	}

	return nil
}

func checkJarFile(proc *process.Process, entry *ReportEntry, openFile process.OpenFilesStat) error {
	f, err := os.Open(pathForFile(proc, openFile))
	if err != nil {
		return fmt.Errorf("error opening file %q: %w", openFile.Path, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("error calling Stat() on file %q: %w", openFile.Path, err)
	}

	// Ignore things that aren't files
	if !fi.Mode().IsRegular() {
		return nil
	}

	r, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return fmt.Errorf("error opening file %q: %w", openFile.Path, err)
	}

	// Check for files matching the word "log4j" in them
	for _, f := range r.File {
		if strings.Contains(f.Name, "log4j") {
			hash := "error"
			if fr, err := r.Open(f.Name); err == nil {
				hash = hashFsFile(fr)
				fr.Close()
			}

			entry.Log4JFiles = append(entry.Log4JFiles, FileEntry{
				ContainedIn: openFile.Path,
				Path:        f.Name,
				SHA256:      hash,
			})
		}
	}

	// Also, if this is a deploy/uber-jar, we may have log4j in it even if
	// the file name doesn't contain that; try to get that version as well.
	if ver := versionFromJARArchiveFingerprint(r); ver != "unknown" {
		var versionObj *version.Version
		if vo, err := parseVersion(ver); err == nil {
			versionObj = vo
		} else {
			log.Printf("error parsing %q: %v", ver, err)
		}

		entry.JARs = append(entry.JARs, JAREntry{
			Path:       openFile.Path,
			VersionStr: ver,
			VersionObj: versionObj,
			// TODO: SHA256:     hash,
		})
	}
	return nil
}

func pathForFile(proc *process.Process, openFile process.OpenFilesStat) string {
	return fmt.Sprintf("/proc/%d/fd/%d", proc.Pid, openFile.Fd)
}

func getSysprops(proc *process.Process) (map[string]string, error) {
	// Use the jinfo from "next" to the java process, if it exists
	jinfoPath := "/usr/bin/jinfo"
	if s, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", proc.Pid)); err == nil {
		tpath := filepath.Join(filepath.Dir(s), "jinfo")
		if fileExists(tpath) {
			jinfoPath = tpath
		}
	}
	if !fileExists(jinfoPath) {
		return nil, fmt.Errorf("no jinfo found")
	}

	var stdout bytes.Buffer
	cmd := exec.Command(jinfoPath, fmt.Sprint(proc.Pid))
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	ret := make(map[string]string)
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "=", 2)
		if len(parts) == 2 {
			ret[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ret, nil
}

type ReportEntry struct {
	PID      int32
	ProcName string

	// Environment variables
	Environ map[string]string

	// List of system properties set for the process
	SystemProperties map[string]string

	// JAR files
	JARs []JAREntry

	// Log4J-related files in a JAR file
	Log4JFiles []FileEntry
}

type JAREntry struct {
	Path       string
	VersionStr string
	VersionObj *version.Version
	SHA256     string
}

type FileEntry struct {
	Path        string
	ContainedIn string // optional
	SHA256      string
}

// Returns the property values in a consistently-sorted format
func (r ReportEntry) PropertyValues() []string {
	vs := make([]string, 0, len(r.SystemProperties))
	for _, key := range r.PropertyNames() {
		vs = append(vs, r.SystemProperties[key])
	}
	return vs
}

// Returns the property names in a consistently-sorted format.
func (r ReportEntry) PropertyNames() []string {
	ks := make([]string, 0, len(r.SystemProperties))
	for k := range r.SystemProperties {
		ks = append(ks, k)
	}

	sort.Strings(ks)
	return ks
}

func (r ReportEntry) UsingLog4j() bool {
	return len(r.JARs) > 0 || len(r.Log4JFiles) > 0
}
