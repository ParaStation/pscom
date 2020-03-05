#!/bin/sh

VERSION_FILE="${1-vc_version.h}"
VC_VERSION="$(cd $(dirname $0) && ./vcversion -r .. -n)"

cat > $VERSION_FILE~ <<EOF
#define VC_VERSION "${VC_VERSION}"
EOF

if cmp -s "${VERSION_FILE}~" "${VERSION_FILE}"; then
	rm "${VERSION_FILE}~";
else
	mv "${VERSION_FILE}~" "${VERSION_FILE}";
fi
