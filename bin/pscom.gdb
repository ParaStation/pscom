#
# ParaStation
#
# Copyright (C) 2009-2021 ParTec Cluster Competence Center GmbH, Munich
# Copyright (C) 2021-2026 ParTec AG, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#
######################################################################
#
# call this via:
# > gdb -x pscom.gdb
# or at the gdb prompt:
# (gdb) source pscom.gdb
# To print information about all connections:
# (gdb) print_all

define list_entry
        set $ret=($arg1*)((char*)$arg0-(unsigned long)&((($arg1*)0)->$arg2))
end


define list_count
	set $i=$arg0
	set $istart=$i
	set $ret=0
	while ($i->next != $istart && $ret < 999)
		set $ret=$ret+1
		set $i=$i->next
	end
	if ($ret>=999)
		echo Warning: list >= 999 entries!\n
	end
end


define print_con
	printf "con: Magic:%s ", $con->magic == 0x78626c61 ? "ok" : "error"
	output $con->pub.type
	printf "\t"
	output $con->pub.state
	printf "\t%s", pscom_con_info_str(&$con->pub.remote_con_info)
	if ($con->pub.state == PSCOM_CON_STATE_RW)
		list_count &$con->sendq
		printf "\tsendq:%u\n", $ret
	else
		printf "\n"
	end
	if ($con->pub.type == PSCOM_CON_TYPE_OPENIB)
		printf " outstanding_cq_entries:%u n_send_toks:%u n_tosend_toks:%u n_recv_toks:%u\n", \
			$con->arch.openib.mcon->outstanding_cq_entries, \
			$con->arch.openib.mcon->n_send_toks, \
			$con->arch.openib.mcon->n_tosend_toks, \
			$con->arch.openib.mcon->n_recv_toks
		set $hasib=1
	end
	if ($con->pub.type == PSCOM_CON_TYPE_DAPL)
		printf " outstanding_cq_entries:%u n_send_toks:%u n_tosend_toks:%u n_recv_toks:%u\n", \
			$con->arch.dapl.ci->outstanding_cq_entries, \
			$con->arch.dapl.ci->n_send_toks, \
			$con->arch.dapl.ci->n_tosend_toks, \
			$con->arch.dapl.ci->n_recv_toks
		set $hasdapl=1
	end
end


define init_con
	list_entry pscom.sockets.next pscom_sock_t next
	set $sock=$ret
	printf "sock: Magic:%s ", $sock->magic == 0x6a656e73 ? "ok" : "error"
	printf " listen:%s\n", pscom_con_info_str(&$sock->pub.local_con_info)

	if ($sock.connections.next != &$sock.connections.next)
		list_entry $sock.connections.next pscom_con_t next
		set $con=$ret
	else
		printf "No connection\n"
	end
end


define _next_con
	list_entry $con->next.next pscom_con_t next
	set $con=$ret
end


define next_con
	_next_con
	if (&$con->next != &$sock->connections.next)
		print_con
	else
		if ($sock.connections.next != &$sock.connections.next)
			printf "- First connection ----------------\n"
			next_con
		else
			printf "No connection\n"
		end
	end
end


define print_all
	# List connection specific information
	init_con
	set $hasib=0
	set $hasdapl=0
	while (&$con->next != &$sock->connections.next)
		print_con
		_next_con
	end

	if ($hasib)
		printf "psoib_outstanding_cq_entries: %u\n", psoib_outstanding_cq_entries
		printf "psoib_stat:"
		output psoib_stat
		printf "\n"
	end
	if ($hasdapl)
		printf "psdapl_stat:"
		output psdapl_stat
		printf "\n"
	end
	printf "pscom.stat:"
	output pscom.stat
	printf "\n"
end


define print_dump
       printf "%s\n", pscom_dump_str(10)
end
