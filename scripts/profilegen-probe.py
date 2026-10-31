#!/usr/bin/env python3
"""Print what the store profile generator actually has in memory.

The emulator stops on a Swift type whose metadata page ships as zeroes, and the
profile records sixteen other types pointing into that same page. collect.go
decides each page's bytes with

    if !v.mapped[a] && (a < bootHeap || a >= bootHeap+v.cursor) {
        return v.source.read(a, 4096)   // not mapped: read the file, which is zero
    }

so an unmapped cache page is emitted from the file no matter what the guest did.
Whether that is what happens here is a two-line question and this script asks it
inside the generator, where the answer lives.

It does not change behaviour: it prints, then removes nothing.
"""

import subprocess
import sys

PROBE = '''
	// --- store profile probe: what is actually in memory? ---
	{
		const probePage = 0x1e64da000

		keys := make([]string, 0, len(p.SwiftTypes))
		for k := range p.SwiftTypes {
			keys = append(keys, k)
		}

		sort.Strings(keys)

		fmt.Fprintf(os.Stderr, "[probe] swift types=%d mapped pages=%d page %#x mapped=%v\\n",
			len(p.SwiftTypes), len(v.mapped), probePage, v.mapped[probePage])

		nonzero := 0

		if v.mapped[probePage] {
			b := v.read(probePage, 4096)
			for _, c := range b {
				if c != 0 {
					nonzero++
				}
			}

			fmt.Fprintf(os.Stderr, "[probe] page %#x in guest: nonzero=%d first16=%x\\n",
				probePage, nonzero, b[:16])
		}

		shown := 0

		for _, k := range keys {
			value := p.SwiftTypes[k]
			if value&^0xfff != probePage {
				continue
			}

			head := "unmapped"

			if v.mapped[value&^0xfff] {
				head = fmt.Sprintf("%x", v.read(value, 16))
			}

			fmt.Fprintf(os.Stderr, "[probe] type %s -> %#x head=%s\\n", k, value, head)

			shown++
			if shown >= 6 {
				break
			}
		}
	}
'''

ANCHOR = "\tpages := v.collect(p, classes)"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: profilegen-probe.py <ipatool-checkout>", file=sys.stderr)

        return 2

    path = f"{sys.argv[1]}/internal/store/profilegen/generate.go"

    with open(path, encoding="utf-8") as handle:
        source = handle.read()

    if "[probe] swift types" in source:
        print("probe already present")

        return 0

    if ANCHOR not in source:
        print(f"anchor not found in {path}; the upstream file changed", file=sys.stderr)

        return 1

    source = source.replace(ANCHOR, PROBE + ANCHOR, 1)

    # sort and os are needed by the probe only.
    for pkg in ("sort", "os"):
        if f'"{pkg}"' not in source:
            source = source.replace('import (\n', f'import (\n\t"{pkg}"\n', 1)

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(source)

    # The two imports land where they were inserted rather than in order. gofmt
    # is on the runner because the generator is built there; if it is missing the
    # file is still valid Go, just unsorted.
    try:
        subprocess.run(["gofmt", "-w", path], check=False, capture_output=True)
    except OSError:
        pass

    print(f"probe inserted into {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
