// Command x86inventory inspects the OS X 10.9 SAP assets.
//
// These are the x86-64 binaries ipatool-rs runs under a CPU emulator, and the
// reason they matter here is that the TCI (tiny code interpreter) build of
// Unicorn only has an x86 frontend enabled in the configuration we would
// need: the interpreter never asks the host for executable memory, which is
// the one hard limit on a non-jailbroken device.
//
// Before any of that is worth building, the binaries have to look like
// something the existing shim layer could serve. That means answering:
//
//   - what architecture and file type are they
//   - do they use chained fixups at all (2013 binaries may predate them)
//   - how many rebase and bind fixups are there
//   - what external symbols do they import, and which libraries provide them
//   - are the entry points our machine package resolves still exported
//
// Usage:
//
//	x86inventory -dir <directory-of-extracted-assets>
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

type dep struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type report struct {
	File          string   `json:"file"`
	Error         string   `json:"error,omitempty"`
	CPU           string   `json:"cpu"`
	Subtype       string   `json:"cpu_subtype"`
	FileType      string   `json:"filetype"`
	ChainedFixups bool     `json:"chained_fixups"`
	DyldInfo      bool     `json:"dyld_info"`
	PointerFormat string   `json:"pointer_format,omitempty"`
	ImportCount   int      `json:"import_count"`
	RebaseCount   int      `json:"rebase_count"`
	BindCount     int      `json:"bind_count"`
	Exports       int      `json:"export_count"`
	HasSAPEntries bool     `json:"has_sap_entry_symbols"`
	SAPEntries    []string `json:"sap_entries_found,omitempty"`
	Dependencies  []dep    `json:"dependencies"`
	TopImports    []string `json:"top_imports,omitempty"`
	AllImports    []string `json:"all_imports,omitempty"`
}

// The entry points machine/machine.go resolves out of CoreFP today, plus the
// AppleMediaServices ones. If the 2013 CoreFP still exports these, the shim
// layer's expectations carry over unchanged.
var coreFPEntries = []string{
	"_WIn9UJ86JKdV4dM",
	"_X46O5IeS",
	"_YlCJ3lg",
	"_dku592fbFAj",
	"_fdjkDSAFjklaf2s",
	"_lxpgvVMLd0S7uRl",
}

var commerceEntries = []string{
	"_cp2g1b9ro",
	"_Mib5yocT",
	"_Fc3vhtJDvr",
	"_IPaI1oem5iL",
	"_jEHf8Xzsv8K",
}

func main() {
	dir := flag.String("dir", "", "directory holding the extracted OS X 10.9 assets")
	flag.Parse()

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: x86inventory -dir <directory>")
		os.Exit(2)
	}

	entries, err := os.ReadDir(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", *dir, err)
		os.Exit(1)
	}

	reports := []report{}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "CoreFP.icxs" {
			continue
		}
		reports = append(reports, inspect(filepath.Join(*dir, entry.Name()), entry.Name()))
	}

	encoded, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(encoded))
}

func inspect(path, name string) report {
	out := report{File: name}

	raw, err := os.ReadFile(path)
	if err != nil {
		out.Error = err.Error()
		return out
	}

	file, err := openX86(raw)
	if err != nil {
		out.Error = err.Error()
		return out
	}

	out.CPU = fmt.Sprintf("%v", file.FileHeader.CPU)
	out.Subtype = fmt.Sprintf("%v", file.FileHeader.SubCPU)
	out.FileType = fmt.Sprintf("%v", file.FileHeader.Type)
	out.Dependencies = dependencies(file)

	symbols, err := file.ImportedSymbols()
	if err == nil {
		names := make([]string, 0, len(symbols))
		for _, s := range symbols {
			names = append(names, s.Name)
		}
		out.ImportCount = len(names)
		out.TopImports = sample(names, 25)
		all := append([]string{}, names...)
		sort.Strings(all)
		out.AllImports = all
	}

	out.ChainedFixups = file.HasDyldChainedFixups()
	out.DyldInfo = file.HasDyldInfoOnly() || file.DyldInfo() != nil

	if out.ChainedFixups {
		chains, err := file.DyldChainedFixups()
		if err != nil {
			out.Error = "parse chained fixups: " + err.Error()
			return out
		}
		if _, err := chains.Parse(); err != nil {
			out.Error = "walk chains: " + err.Error()
			return out
		}
		out.PointerFormat = fmt.Sprintf("%v", chains.PointerFormat)

		for _, start := range chains.Starts {
			for _, fixup := range start.Fixups {
				switch {
				case fixup.IsRebase():
					out.RebaseCount++
				case fixup.IsBind():
					out.BindCount++
				}
			}
		}
	}

	// Exported symbols: does the binary still name the entry points the
	// existing machine package resolves?
	wanted := append(append([]string{}, coreFPEntries...), commerceEntries...)
	for _, symbol := range wanted {
		if _, err := file.FindSymbolAddress(symbol); err == nil {
			out.SAPEntries = append(out.SAPEntries, symbol)
		}
	}
	out.HasSAPEntries = len(out.SAPEntries) > 0

	if exports, err := file.GetExports(); err == nil {
		out.Exports = len(exports)
	}

	return out
}

// openX86 picks the x86_64 slice. These assets are universal binaries whose
// first slice is i386, so taking the first one would inspect the wrong
// architecture.
func openX86(raw []byte) (*macho.File, error) {
	if fat, err := macho.NewFatFile(bytes.NewReader(raw)); err == nil {
		for _, arch := range fat.Arches {
			if arch.File.FileHeader.CPU == types.CPUAmd64 {
				return arch.File, nil
			}
		}
		for _, arch := range fat.Arches {
			if arch.File.FileHeader.CPU == types.CPUI386 {
				return arch.File, nil
			}
		}
		return nil, fmt.Errorf("universal binary has no x86 slice (%d present)", len(fat.Arches))
	}

	return macho.NewFile(bytes.NewReader(raw))
}

func dependencies(file *macho.File) []dep {
	out := []dep{}
	for _, load := range file.Loads {
		switch typed := load.(type) {
		case *macho.LoadDylib:
			out = append(out, dep{Name: typed.Name, Kind: "load"})
		case *macho.WeakDylib:
			out = append(out, dep{Name: typed.Name, Kind: "weak"})
		case *macho.LazyLoadDylib:
			out = append(out, dep{Name: typed.Name, Kind: "lazy"})
		case *macho.ReExportDylib:
			out = append(out, dep{Name: typed.Name, Kind: "reexport"})
		case *macho.IDDylib:
			out = append(out, dep{Name: typed.Name, Kind: "id"})
		}
	}
	return out
}

func sample(names []string, limit int) []string {
	out := append([]string{}, names...)
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

var _ = strings.TrimSpace
