#!/bin/bash
#:
#: name = "build / illumos"
#: variety = "basic"
#: target = "helios"
#: rust_toolchain = "stable"
#: output_rules = [
#:	"/work/awl.*",
#: ]
#: access_repos = [
#:   "oxidecomputer/yoursecretsgivethemtome",
#: ]

set -o errexit
set -o pipefail
set -o xtrace

rustc --version

banner build
ptime -m cargo build --release

banner package
cp target/release/aws-wire-lengths /work/awl
digest -a sha256 /work/awl > /work/awl.sha256.txt
gzip /work/awl
digest -a sha256 /work/awl.gz > /work/awl.gz.sha256.txt
