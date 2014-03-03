#!/bin/bash
#
# (c) 2009-07-02 Jens Hauke <hauke@par-tec.com>
#
PSIADMIN="@bindir@/psiadmin"

arg_cmd='ssh -n $host gdb --batch -x @configdir@/pscom.gdb -ex bt -ex print_all -p $pid'
# pssh command: "cat" is used to loose the pty on stdout
arg_pssh_cmd='pssh -n $node gdb --batch -x @configdir@/pscom.gdb -ex bt -ex print_all -p $pid | cat'
arg_host=$(hostname)

function vecho(){ [ -z $arg_verbose ] || echo "$@"; }

function usage(){
    cat <<EOF
Usage:
  $BASH_SOURCE [OPTION]... [FILE]...

  -l, --logger=TID    processes with ptid==TID
  --host=HOSTNAME     Use first logger on host HOSTNAME as ptid
  -c, --cmd=CMD       command to call. Following variables
                      will be set:
                        \$tid, \$rank, \$node, \$pid, \$host
                      default is '$arg_cmd'
  -p, --pssh          Use pssh: '$arg_pssh_cmd'

  -v                  verbose
  -h, --help          help
EOF
    exit 0
}

function parse_arg() {
    while [ $# -gt 0 ]; do
	case "$1" in
	    -c|--cmd)		shift; arg_cmd="$1";;
	    -l|--logger)	shift; arg_logger="$1";;
	    -p|--pssh)		arg_cmd="$arg_pssh_cmd";;
	    --host)		shift; arg_host="$1";;
	    --help|-h)		usage;;
	    --verbose|-v)	arg_verbose=1;;
	    --)			shift;break;;
	    --#*|'')		return;;
	    *)			echo "WARNING: unhandled option '$1'";;
	esac
	shift
    done
    arg_files=("${arg_files[@]}" "$@")
}


# Need TEMP to get the return code from getopt.
TEMP=$(getopt -n"$BASH_SOURCE" -a -l "cmd:,logger:,host:,help,pssh,verbose" "c:l:vph" "$@")

[ "$?" != 0 ] && usage

# getopt take care of quoting, eval will unquote.
eval parse_arg "$TEMP"


[ -z "$arg_logger" ] && arg_logger="${arg_files[0]}"

if [ -z "$arg_logger" ]; then
    # ToDo: Use -1 instead of hostname (need psmgmt > 5.0.16-2)
    arg_logger=$($PSIADMIN -c "l p $arg_host" | grep -E "\(L\)\$"| { read node tid ptid con uid rank cmd; echo $tid;})
    vecho "Use logger with tid: $arg_logger"
fi
if [ -z "$arg_logger" ]; then
    echo "Missing argument --logger. e.g. --logger=0x00002ef0"
    exit 1
fi

vecho "--cmd='$arg_cmd'"

function do_cmd(){
    local tid="$1"
    local rank="$2"
    local node="${tid#*[}"; node="${node%:*}"
    local pid="${tid#*:}"; pid="${pid%]}"
    local host="$($PSIADMIN -c "reso $node"|{ read n h; echo $h; })"
    echo "======== rank $rank ========== node:$node host:$host"
    eval "echo -E $arg_cmd"
    eval "$arg_cmd"
    :
}

$PSIADMIN -c "l p"| sort -nk 6 | while read node tid ptid con uid rank cmd; do
    case "$ptid" in
	"$arg_logger"*)	    </dev/null do_cmd "$tid" "$rank";;
    esac
done




# Local Variables:
#  compile-command: "./jobinfo"
# End:
