#!/bin/sh
# Materialise the ./.etls-patched replacement directory: copy the go.mod-pinned
# gitlab.com/go-extension/tls version out of the module cache and apply every
# patch in third_party/patches/ (numbered order).  Any patch that fails to
# apply aborts the build loudly — that means upstream drifted; see
# third_party/patches/README.md for the re-sync procedure.
#
# Run once per fresh clone and after every eTLS version bump.  Until it has
# run, every go command fails with:
#   "replacement directory ./.etls-patched does not exist"
set -eu

MODULE=gitlab.com/go-extension/tls
DEST=.etls-patched

cd "$(dirname "$0")/.."

VER=$(grep -E "^[[:space:]]*gitlab\.com/go-extension/tls v" go.mod | head -1 | awk '{print $2}')
if [ -z "${VER}" ]; then
	echo "prepare-etls: cannot find ${MODULE} version in go.mod" >&2
	exit 1
fi

# Fetch the pinned version into the module cache WITHOUT loading this repo's
# go.mod: the replace directive points at ${DEST}, which does not exist yet —
# a plain `go mod download` here would fail on it.  A throwaway module in a
# temp dir has no such replace.
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT
(
	cd "${TMP}/m" 2>/dev/null || { mkdir "${TMP}/m" && cd "${TMP}/m"; } # go refuses a go.mod in the system temp root
	go mod init tmp >/dev/null 2>&1
	go mod edit -require="${MODULE}@${VER}"
	GOFLAGS=-mod=mod go mod download "${MODULE}@${VER}" >/dev/null
)

SRC="$(go env GOMODCACHE)/${MODULE}@${VER}"
if [ ! -d "${SRC}" ]; then
	echo "prepare-etls: ${SRC} not found after download" >&2
	exit 1
fi

# Wipe any previous generation but keep the tracked bootstrap README (it is
# the only git-visible file in this gitignored directory).
if [ -d "${DEST}" ]; then
	find "${DEST}" -mindepth 1 -maxdepth 1 ! -name README.md -exec rm -rf {} +
else
	mkdir -p "${DEST}"
fi
cp -R "${SRC}/." "${DEST}/"
chmod -R u+w "${DEST}"
for p in third_party/patches/*.patch; do
	echo "prepare-etls: applying $(basename "${p}")"
	git apply --directory="${DEST}" "${p}"
done

echo "prepare-etls: ${MODULE}@${VER} + patches -> ${DEST}/"
