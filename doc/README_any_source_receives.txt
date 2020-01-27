-*- text -*-

= General =

 ANY_SOURCE receive requests::
   receive requests on a socket without a specified connection, where
   the message should arrive. (con = NULL, sock != NULL)

 SOURCED receives::
   receive requests for a connection. The source of the message is
   specified by con. (con != NULL, sock = undefined)


= Queues =
 sock->genrecvq_any::
   queue for incoming messages without a matching receive
   request. Shared between all connections of a sock. Ordered by the
   time of arrival.

 con->net_recvq_user::
   queue for incoming messages without a matching receive
   request on connection con. Ordered by the time of arrival.

 sock->recvq_any::
   queue of all posted receive ANY_SOURCE requests and all posted
   SOURCED receive requests after an ANY_SOURCE request.

= Usage counter =

 sock->recv_req_cnt_any::
   Count ANY_SOURCE receives on a socket. Current implementation call
   inc/dec con->recv_req_cnt on all associated connections on the 0->1
   (inc on all connections) edge and 1->0 edge (dec all
   connections). con->read_stop() will not explicit be called (but
   should at cnt=0 See Ticket #712).

 con->recv_req_cnt::
   Count all "users" with a pending receive request on connection
   con. Call con->read_start() on the 0->1 edge. Does not automatic
   call con->read_stop() on 1->0! The zero user check is explicit
   checked with pscom_con_check_read_stop() and calls
   con->read_stop() in case of cnt==0.




= Receiving messages =

Start receiving of a message on connection con

 * Search for a matching request in con->recvq_user.

 * Else search for a matching request in sock->recvq_any.

 * Dequeue request from sock->recvq_any or con->recvq_user.

 * If SOURCED request, decrement the con->recv_req_cnt usage
   counter. (But do not call con->read_stop()!)

 * If ANY_SOURCE request, decrement the virtual
   "sock->recv_req_cnt_any" usage counter. (But do not call
   con->read_stop() on any connection!)

Finishing a receive request. (Last byte received)

 * Check con->recv_req_cnt (pscom_con_check_read_stop())
   If and only if connection has no pending receive requests
   (con->recv_req_cnt == 0) AND no active receive on this connection
   (con->in.req != NULL) AND pscom.env.unexpected_receives not
   switched on, then call con->read_stop().

The Ticket #712: con->read_stop() not called on many connections after
an ANY_SOURCE receive.
 * Plugins with linear ANY_SOURCE scaling (openib, extoll) now check
   if they should call con->read_stop() in pscom_xxx_on_read()
   (pscom_con_check_read_stop(con)).

= Posting receives =

== Posting an ANY_SOURCE request ==

 * search for a generated request in sock->genrecvq_any. Use this, if
   found.

 * Enqueue request to sock->recvq_any.

 * Increment the virtual "sock->recv_req_cnt_any" usage counter.

== Posting a SOURCED request ==

 * search for a generated request in con->net_recvq_user. Use this, if
   found.

 * Enqueue request to

    * con->recvq_user if and only if sock->recvq_any is empty

    * sock->recvq_any if sock->recvq_any is NOT empty. (At least one
      ANY_SOURCE receive request posted)

 * Increment the con->recv_req_cnt usage counter



Local Variables:
  ispell-local-dictionary: "american"
End:
