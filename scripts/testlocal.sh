#!/bin/bash
MSG_SIZE=$((32*1024))
export PSP_SHM=2
export PSP_TCP=0
export PSP_DEBUG=3

# Return with an exit code if the pscom_pp server fails
set -e -o pipefail

# Run the server
../bin/pscom_pp -1 -V | while read -t 10 cmd args; do
	case $cmd in
		# Run the client with arguments we got from the server:
		# > Waiting for client.
		# > Call client with:
		# > ./pscom_pp -c 192.168.1.1:7100

		*pscom_pp)
			$cmd $args --minsize=${MSG_SIZE} --maxsize=${MSG_SIZE} -V
			;;
	esac
done
