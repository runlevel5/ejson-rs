#!/bin/sh
# Build the RPM from a freshly vendored source tarball (run from anywhere in
# the repo; needs network access to fetch crates for `cargo vendor`).
set -eu

ROOT="$(git rev-parse --show-toplevel)"
VERSION=$(grep '^version' "$ROOT/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
NAME="ejson-${VERSION}"
TOP="$ROOT/build/rpm/rpmbuild"
STAGE="$TOP/SOURCES/$NAME"

rm -rf "$STAGE"
mkdir -p "$STAGE" "$TOP/SOURCES"
git -C "$ROOT" archive HEAD | tar -x -C "$STAGE"

# Vendor everything into the tarball and point cargo at it for an offline
# build, instead of relying on cargo-rpm-macros' system crate registry.
(
  cd "$STAGE"
  mkdir -p .cargo
  cargo vendor --locked vendor > .cargo/config.toml
)

tar cJf "$TOP/SOURCES/${NAME}-vendored.tar.xz" -C "$TOP/SOURCES" "$NAME"
rm -rf "$STAGE"

rpmbuild --define "_topdir $TOP" -bb "$ROOT/build/rpm/ejson.spec"

echo "RPMs are in $TOP/RPMS/"
