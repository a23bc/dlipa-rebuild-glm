#!/usr/bin/env bash
# Fails when app source reaches for an API newer than the minimum
# deployment target set in app/project.yml (iOS 15.0).
#
# SwiftLint cannot do this and neither can anything else short of the
# compiler, which here means a macOS runner that answers six to eight
# minutes after the push. A name list is the cheap version: it catches the
# APIs that are easy to write from habit -- @Observable, NavigationStack,
# Mutex -- in three seconds, on any machine with bash, including a Windows
# one.
#
# It is a list of names, not a type checker. It will miss an iOS 17
# argument added to a method that has existed since iOS 13. It will also
# over-report when one of these names belongs to this project. Silence a
# genuine false positive by putting "ios15-ok:" anywhere on the line.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
search_dirs=("$repo_root/app" "$repo_root/probeapp")

apis=(
	# iOS 17: Observation, SwiftData, and the SwiftUI additions that came with them.
	'@Observable'
	'@Bindable'
	'import Observation'
	'import SwiftData'
	'ContentUnavailableView'
	'onGeometryChange'
	'\.onChange\(of:[^)]*initial:'
	'\bDuration\('
	'\bglassEffect'
	'\bToolbarSpacer\b'
	'\.buttonSizing\('
	'\.scrollClipDisabled'
	'\.presentationBackground'
	'\.scrollPosition\(id:'
	'\.defaultScrollAnchor'
	# iOS 18: Synchronization, the new Section and Tab shapes, and the
	# environment-entry declaration macro.
	'\bMutex\b'
	'import Synchronization'
	'@Entry'
	'\bSectionConfiguration\b'
	'\.tabViewStyle\(\.interactiveSwitcher'
	'\bTab\(role:'
	'Group\(subviews:'
	# iOS 16: NavigationStack and everything that arrived with it.
	'NavigationStack'
	'\.navigationDestination\('
	'\.navigationSubtitle'
	'presentationDetents'
	'\bAnyLayout\b'
	'\bViewThatFits\b'
	'\bProposedViewSize\b'
	'\bImageRenderer\b'
	'\bShareLink\b'
	'\bRegex\b'
	'\bURL\(filePath:'
	'\.host\(\)'
	'\bGrid\('
	'\bPhotosPicker\b'
	'\.scrollTargetBehavior'
	'\.containerRelativeFrame'
	'\.symbolVariableColor'
	'\.inspector\('
)

pattern=$(printf '%s|' "${apis[@]}")
pattern=${pattern%|}

hits=$(
	grep -rnE --include='*.swift' "$pattern" "${search_dirs[@]}" |
		grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|/\*|\*|\*/)' |
		grep -v 'ios15-ok:' || true
)

if [ -n "$hits" ]; then
	echo "These lines use APIs newer than the iOS 15 deployment target:"
	echo
	echo "$hits"
	echo
	echo "Back-port them, or mark a false positive with \"ios15-ok:\" on the line."
	exit 1
fi

echo "No post-iOS-15 API names found in $(find "${search_dirs[@]}" -name '*.swift' | wc -l | tr -d ' ') Swift files."
