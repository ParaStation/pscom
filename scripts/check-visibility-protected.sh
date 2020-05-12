#!/bin/sh

checkvisibility1c=$(mktemp --tmpdir check-visibility-protected-1.XXXXX.c)
checkvisibility2c=$(mktemp --tmpdir check-visibility-protected-2.XXXXX.c)
CC="${CC-cc}"

cat > "$checkvisibility1c" <<EOF
		int bar __attribute__ ((visibility ("protected"))) = 1;

		__attribute__ ((visibility ("protected")))
		int bla(void) { return bar; };
EOF

cat > "$checkvisibility2c" <<EOF
		  extern int bar;
		  int bla(void);
		  int main (void) { return bar + bla(); }
EOF
# echo "Check for working '__attribute__ ((visibility ("protected")))': ${CC}"

set -x
"${CC}" -nostdlib -nostartfiles -fPIC -shared "${checkvisibility1c}" -o "${checkvisibility1c}.so"
"${CC}" "${checkvisibility2c}" "${checkvisibility1c}.so" -o "${checkvisibility2c}.x"

ret=$?
[ $ret = 0 ] && resstr="works" || resstr="failed"
echo "Check for working '__attribute__ ((visibility ("protected")))': ${CC} -- $resstr"

rm -f "${checkvisibility1c}" "${checkvisibility2c}" "${checkvisibility1c}.so" "${checkvisibility2c}.x"

exit "$ret"

# Local Variables:
#  compile-command: "./check-visibility-protected.sh"
# End:
