#!/bin/sh

VERSION_FILE="${1-VERSION.pscom}"
VC_VERSION="$(cd $(dirname $0) && ./vcversion -r .. -n)"
export LC_ALL=C
cat > $VERSION_FILE <<EOF
pscom ${VC_VERSION} ($(date))
EOF
