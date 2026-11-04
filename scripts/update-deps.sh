#!/bin/sh
# update-deps.sh — refresh the tracked direct dependencies (weekly review).
# Usage: sh scripts/update-deps.sh
#
# The eTLS bump needs the dropreplace / go-get-master / re-replace dance from
# the Dockerfile: with the replace directive active a plain `go get` silently
# no-ops the module (see third_party/patches/README.md §Version tracking).
# A patch that no longer applies to master aborts the second prepare-etls
# loudly — regenerate it per README §Re-sync.
set -eu

cd "$(dirname "$0")/.."

run() {
	echo "+ $*"
	"$@"
}

# If the master dance fails halfway, re-add the replace so go.mod stays
# buildable against the previously prepared ./.etls-patched tree.
restore_replace() {
	go mod edit -replace=gitlab.com/go-extension/tls=./.etls-patched
}

# ./.etls-patched must exist before any go command while the replace is active.
sh scripts/prepare-etls.sh

run go get -u codeberg.org/miekg/dns@main
run go get -u gitee.com/Trisia/gotlcp@main
run go get -u github.com/cloudflare/circl@main
run go get -u github.com/klauspost/compress@master
run go get -u github.com/pion/dtls/v4@main
run go get -u github.com/quic-go/quic-go@master

# eTLS master dance.
trap restore_replace EXIT
run go mod edit -dropreplace=gitlab.com/go-extension/tls
run go get -u gitlab.com/go-extension/tls@master
run go mod edit -replace=gitlab.com/go-extension/tls=./.etls-patched
trap - EXIT

sh scripts/prepare-etls.sh

run go mod tidy
echo "update-deps: done — review git diff go.mod go.sum before committing"
