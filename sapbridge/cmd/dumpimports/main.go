// Command dumpimports reports the external symbol surface of the pinned Apple
// SAP assets.
//
// It exists to answer one question, and only that question: if we stop
// emulating CoreFP / AppleMediaServices under Unicorn and instead let iOS dyld
// load them directly (the dlopen path), which imports must dyld resolve on
// iOS, and is every one of them satisfiable by an iOS framework?
//
// Emulation hides this: the shims in package machine answer external calls
// themselves, so a missing import only shows up as "the shim returned
// something". Under dlopen there are no shims — dyld either binds the symbol
// or the load fails.
//
// The asset binaries live outside this repository (VendorAssets/, git-lfs), so
// this program can only be run where those files exist: the macOS CI runner.
//
// Usage:
//
//	dumpimports -assets DIR -machine-dir DIR [-out report.json]
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

// assets are the Mach-O images to inspect. CoreFP.icxs is a data blob, not a
// Mach-O, so it is deliberately absent.
var assets = []string{"CoreFP", "AppleMediaServices", "commerce"}

type dependency struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type report struct {
	File          string       `json:"file"`
	FileType      string       `json:"filetype"`
	CPU           string       `json:"cpu"`
	Platform      string       `json:"platform"`
	ChainedFixups bool         `json:"chained_fixups"`
	DyldInfoOnly  bool         `json:"dyld_info_only"`
	ImportSource  string       `json:"import_source"`
	ImportCount   int          `json:"import_count"`
	Note          string       `json:"note,omitempty"`
	Dependencies  []dependency `json:"dependencies"`
	Imports       []string     `json:"imports,omitempty"`
	Error         string       `json:"error,omitempty"`
}

func main() {
	assetsDir := flag.String("assets", "", "directory holding the staged Apple SAP assets")
	machineDir := flag.String("machine-dir", "", "directory of package machine, scanned for known external symbols")
	out := flag.String("out", "", "write the JSON report here as well as to stdout")
	flag.Parse()

	if *assetsDir == "" || *machineDir == "" {
		fmt.Fprintln(os.Stderr, "usage: dumpimports -assets DIR -machine-dir DIR [-out report.json]")
		os.Exit(2)
	}

	reports := make([]report, 0, len(assets))
	for _, name := range assets {
		reports = append(reports, inspect(filepath.Join(*assetsDir, name), name))
	}

	known, err := knownSymbols(*machineDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not read known symbols: %v\n", err)
	}

	document := struct {
		Assets    []report `json:"assets"`
		CrossCheck crossCheckResult `json:"cross_check"`
	}{
		Assets:     reports,
		CrossCheck: crossCheckReports(reports, known),
	}

	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode report: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(encoded))

	if *out != "" {
		if err := os.WriteFile(*out, append(encoded, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", *out, err)
			os.Exit(1)
		}
	}
}

func inspect(path, name string) report {
	result := report{File: name}

	raw, err := os.ReadFile(path)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	file, err := openThin(raw)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.FileType = fmt.Sprintf("%v", file.FileHeader.Type)
	result.CPU = fmt.Sprintf("%v", file.FileHeader.CPU)
	result.ChainedFixups = file.HasDyldChainedFixups()
	result.DyldInfoOnly = file.HasDyldInfoOnly()
	result.Dependencies = dependencies(file)
	result.Imports, result.ImportSource = imports(file)
	result.ImportCount = len(result.Imports)

	if result.ImportCount == 0 {
		// AppleMediaServices is sliced out of the arm64e dyld shared cache, so
		// it carries neither a symbol table nor chained fixups: an empty list
		// here means "this file does not describe its own imports", not "it has
		// none". Its external surface is the hardcoded stub map in macos27.go.
		result.Note = "no import metadata in this image; if it is a shared-cache " +
			"slice its external symbols are the ones package machine maps by address"
	}

	for _, load := range file.Loads {
		if build, ok := load.(*macho.BuildVersion); ok {
			result.Platform = fmt.Sprintf("%v", build.Platform)
			break
		}
	}

	return result
}

// openThin returns the arm64 slice of a Mach-O, handling both thin and fat
// inputs.
//
// CoreFP and commerce are universal binaries whose first slice is x86_64, so
// taking whatever comes first would describe the wrong architecture: the
// numbers that matter here are the ones iOS dyld would have to satisfy.
// Note that types.CPUArm64 formats as "AARCH64", so matching the CPU constant
// and not its name is the only safe test.
func openThin(raw []byte) (*macho.File, error) {
	if fat, err := macho.NewFatFile(bytes.NewReader(raw)); err == nil {
		for _, arch := range fat.Arches {
			if arch.File.FileHeader.CPU == types.CPUArm64 {
				return arch.File, nil
			}
		}

		return nil, fmt.Errorf("universal Mach-O has no arm64 slice (%d present)", len(fat.Arches))
	}

	return macho.NewFile(bytes.NewReader(raw))
}

func dependencies(file *macho.File) []dependency {
	var out []dependency

	for _, load := range file.Loads {
		switch typed := load.(type) {
		case *macho.LoadDylib:
			out = append(out, dependency{Name: typed.Name, Kind: "load"})
		case *macho.WeakDylib:
			out = append(out, dependency{Name: typed.Name, Kind: "weak"})
		case *macho.LazyLoadDylib:
			out = append(out, dependency{Name: typed.Name, Kind: "lazy"})
		case *macho.ReExportDylib:
			out = append(out, dependency{Name: typed.Name, Kind: "reexport"})
		case *macho.IDDylib:
			out = append(out, dependency{Name: typed.Name, Kind: "id"})
		}
	}

	return out
}

// imports returns the external symbols an image needs bound. Chained fixups
// carry the authoritative list; the symbol table is the fallback for images
// that still use classic dyld opcodes.
func imports(file *macho.File) ([]string, string) {
	if file.HasDyldChainedFixups() {
		chains, err := file.DyldChainedFixups()
		if err != nil {
			return nil, "chained-fixups-parse-failed"
		}

		if err := chains.EnsureImports(); err != nil {
			return nil, "chained-fixups-imports-parse-failed"
		}

		names := make([]string, 0, len(chains.Imports))
		for _, entry := range chains.Imports {
			names = append(names, entry.Name)
		}

		return dedup(names), "chained-fixups"
	}

	symbols, err := file.ImportedSymbols()
	if err != nil {
		return nil, "symtab-parse-failed"
	}

	names := make([]string, 0, len(symbols))
	for _, symbol := range symbols {
		names = append(names, symbol.Name)
	}

	return dedup(names), "symtab"
}

func dedup(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}

	sort.Strings(out)

	return out
}

// knownSymbols collects the external symbol names package machine already
// accounts for. Those live in macos27.go and storeagent.go as quoted strings
// starting with an underscore; scanning the directory keeps one source of
// truth instead of duplicating the list here.
func knownSymbols(dir string) (map[string]struct{}, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	pattern := regexp.MustCompile(`"_([A-Za-z0-9_$]+)"`)
	found := make(map[string]struct{})

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}

		source, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}

		for _, match := range pattern.FindAllStringSubmatch(string(source), -1) {
			found["_"+match[1]] = struct{}{}
		}
	}

	return found, nil
}

type crossCheckResult struct {
	KnownCount      int      `json:"known_count"`
	Unresolved      []string `json:"known_but_not_imported"`
	Unexpected      []string `json:"imported_but_not_known"`
	UnexpectedCount int      `json:"unexpected_count"`
}

// crossCheck compares what the shims handle today against what the binaries
// actually import. `Unexpected` is the number that decides the dlopen path:
// every entry there is a symbol iOS dyld would have to bind with no shim
// behind it.
func crossCheckReports(reports []report, known map[string]struct{}) crossCheckResult {
	imported := make(map[string]struct{})
	for _, item := range reports {
		for _, name := range item.Imports {
			imported[name] = struct{}{}
		}
	}

	check := crossCheckResult{KnownCount: len(known)}

	for name := range known {
		if _, ok := imported[name]; !ok {
			check.Unresolved = append(check.Unresolved, name)
		}
	}

	for name := range imported {
		if _, ok := known[name]; !ok {
			check.Unexpected = append(check.Unexpected, name)
		}
	}

	sort.Strings(check.Unresolved)
	sort.Strings(check.Unexpected)
	check.UnexpectedCount = len(check.Unexpected)

	return check
}
