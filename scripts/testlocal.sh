#!/bin/bash -x
MSG_SIZE=$((32*1024))
PSP_ENV="PSP_SHM=1 PSP_TCP=0"

# Run the server
CLIENT_COMMAND_FILE=$(mktemp)
env ${PSP_ENV} ./pscom_pp -1 -V &> ${CLIENT_COMMAND_FILE} &
sleep 1

# Exit if the server could not be started
kill -0 $! || exit 1

# Retrieve client command
CLIENT_COMMAND=$( tail -n 1 ${CLIENT_COMMAND_FILE} )
rm ${CLIENT_COMMAND_FILE}

# Run the client
bash -c "env ${PSP_ENV} ${CLIENT_COMMAND} --minsize=${MSG_SIZE} --maxsize=${MSG_SIZE} -V"
