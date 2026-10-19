// Command fixupinventory counts what a chained-fixup rewrite would have to
// touch, for each pinned Apple SAP asset.
//
// The device settled the constraints: the CPU subtype must be arm64, not
// arm64e, and the platform must be iOS. Both are hard rejections from dyld.
// Chained fixups in either form are accepted, so the format is not the
// problem - the problem is that the subtype change forces the fixup data,
// which is encoded as arm64e chains, to be rewritten too.
//
// Before writing that rewriter, count it. How many rebase fixups are there,
// how many binds, which segments do they land in, are the addends all zero,
// and can every bind ordinal be traced back to a dylib name. Those numbers
// decide the shape of the rewriter and whether it is worth writing at all.
//
// The assets are not in this repository, so this runs in CI:
//
//	DSH_SAP_ASSET_DIR=... go run ./cmd/fixupinventory
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
)

var assets = []string{"CoreFP", "AppleMediaServices", "commerce"}

type segment struct {
	Name      string `json:"name"`
	Index     int    `json:"index"`
	FileOffset uint64 `json:"file_offset"`
	FileSize  uint64 `json:"file_size"`
}

type bindStat struct {
	Name   string `json:"name"`
	Count  int    `json:"count"`
	Addend int64  `json:"addend"`
}

type report struct {
	File             string       `json:"file"`
	Error            string       `json:"error,omitempty"`
	CPU              string       `json:"cpu"`
	Subtype          string       `json:"cpu_subtype"`
	FileType         string       `json:"filetype"`
	ChainedFixups    bool         `json:"chained_fixups"`
	PointerFormat    string       `json:"pointer_format,omitempty"`
	ImportsFormat    string       `json:"imports_format,omitempty"`
	ImportCount      int          `json:"import_count"`
	RebaseCount      int          `json:"rebase_count"`
	BindCount        int          `json:"bind_count"`
	UnknownCount     int          `json:"unknown_count"`
	NonZeroAddends   int          `json:"bind_nonzero_addends"`
	UnresolvedOrdinal int         `json:"bind_unresolved_ordinal"`
	RebaseBySegment  map[string]int `json:"rebase_by_segment,omitempty"`
	BindBySegment    map[string]int `json:"bind_by_segment,omitempty"`
	TopBinds         []bindStat  `json:"top_binds,omitempty"`
	Segments         []segment    `json:"segments"`
}

func main() {
	dir := os.Getenv("DSH_SAP_ASSET_DIR")
	if dir == "" {
		fmt.Fprintln(os.Stderr, "usage: DSH_SAP_ASSET_DIR=... fixupinventory")
		os.Exit(2)
	}

	reports := make([]report, 0, len(assets))
	for _, name := range assets {
		reports = append(reports, inspect(filepath.Join(dir, name), name))
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

	file, err := openThin(raw)
	if err != nil {
		out.Error = err.Error()
		return out
	}

	out.CPU = fmt.Sprintf("%v", file.FileHeader.CPU)
	out.Subtype = fmt.Sprintf("%v", file.FileHeader.SubCPU)
	out.FileType = fmt.Sprintf("%v", file.FileHeader.Type)
	out.Segments = segments(file)

	// A shared-cache slice carries no fixup information of its own, and that
	// is itself the finding: its fixups have to be synthesised, not converted.
	if !file.HasDyldChainedFixups() {
		out.ImportsFormat = "none (no LC_DYLD_CHAINED_FIXUPS)"
		return out
	}

	chains, err := file.DyldChainedFixups()
	if err != nil {
		out.Error = fmt.Sprintf("parse chained fixups: %v", err)
		return out
	}

	if _, err := chains.Parse(); err != nil {
		out.Error = fmt.Sprintf("walk chains: %v", err)
		return out
	}

	if err := chains.EnsureImports(); err != nil {
		out.Error = fmt.Sprintf("parse imports: %v", err)
		return out
	}

	out.ChainedFixups = true
	out.PointerFormat = fmt.Sprintf("%v", chains.PointerFormat)
	out.ImportsFormat = fmt.Sprintf("%v", chains.ImportsFormat)
	out.ImportCount = len(chains.Imports)
	out.RebaseBySegment = map[string]int{}
	out.BindBySegment = map[string]int{}

	counts := map[string]int{}
	addends := map[string]int64{}

	for _, start := range chains.Starts {
		for _, fixup := range start.Fixups {
			segmentName := segmentFor(file, fixup.Offset())

			switch {
			case fixup.IsRebase():
				out.RebaseCount++
				out.RebaseBySegment[segmentName]++
			case fixup.IsBind():
				out.BindCount++
				out.BindBySegment[segmentName]++

				binding, ok := fixup.(fixupchains.Bind)
				if !ok {
					out.UnknownCount++
					continue
				}

				if binding.Addend() != 0 {
					out.NonZeroAddends++
				}

				if binding.Ordinal() >= uint64(len(chains.Imports)) {
					out.UnresolvedOrdinal++
					continue
				}

				symbol := chains.Imports[binding.Ordinal()].Name
				counts[symbol]++
				addends[symbol] = int64(binding.Addend())
			default:
				out.UnknownCount++
			}
		}
	}

	out.TopBinds = topBinds(counts, addends, 20)

	return out
}

func openThin(raw []byte) (*macho.File, error) {
	if fat, err := macho.NewFatFile(bytes.NewReader(raw)); err == nil {
		for _, arch := range fat.Arches {
			// arm64e is CPU_TYPE_ARM64 with subtype 2; we want whichever
			// arm64 slice is present, because that is the one to convert.
			if arch.File.FileHeader.CPU == types.CPUArm64 {
				return arch.File, nil
			}
		}

		return nil, fmt.Errorf("universal Mach-O has no arm64 slice (%d present)", len(fat.Arches))
	}

	return macho.NewFile(bytes.NewReader(raw))
}

func segments(file *macho.File) []segment {
	var out []segment

	index := 0
	for _, load := range file.Loads {
		seg, ok := load.(*macho.Segment)
		if !ok {
			continue
		}
		if seg.Name == "__PAGEZERO" {
			index++
			continue
		}

		out = append(out, segment{
			Name:       seg.Name,
			Index:      index,
			FileOffset: seg.Offset,
			FileSize:   seg.Filesz,
		})
		index++
	}

	return out
}

// segmentFor reports which segment a fixup file offset falls in, so the
// rewriter knows what to put in the segment index of a classic opcode.
func segmentFor(file *macho.File, offset uint64) string {
	for _, seg := range segments(file) {
		if seg.FileSize == 0 {
			continue
		}
		if offset >= seg.FileOffset && offset < seg.FileOffset+seg.FileSize {
			return seg.Name
		}
	}

	return fmt.Sprintf("?offset=%#x", offset)
}

func topBinds(counts map[string]int, addends map[string]int64, limit int) []bindStat {
	out := make([]bindStat, 0, len(counts))
	for name, count := range counts {
		out = append(out, bindStat{Name: name, Count: count, Addend: addends[name]})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}

		return strings.Compare(out[i].Name, out[j].Name) < 0
	})

	if len(out) > limit {
		out = out[:limit]
	}

	return out
}
