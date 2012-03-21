#include "gm_compat.h"
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>


void send_cb(struct gm_port * p,void *context,gm_status_t status)
{
  if (status == GM_SUCCESS)
    ;

//    printf("send ok.\n");
  else
    printf("send not ok: %s.\n",gm_strerror(status));
}

int main(int argc, char**argv)
{

  gm_status_t status;
  struct gm_port *port;
  const unsigned max_size=6;
  gm_size_t length;
  void *rbuffer = 0;
  void *sbuffer = 0;
  gm_recv_event_t* event;
  struct timeval tv1,tv2;
  int sends=0;
  int const max_num_sends = 10000;
  int const our_length = 64-8;

  status = gm_init();

  if (status == GM_SUCCESS){

    status = gm_open(&port, 0, *argv[1]-'0', "bla", GM_API_VERSION_1_1);

    if (status == GM_SUCCESS){


      length=gm_max_length_for_size(max_size);
      fprintf(stderr, "length is %d, our_length is %d.\n", length, our_length);
      sbuffer = gm_dma_malloc(port,length);

      rbuffer = gm_dma_malloc(port,length);

      if (rbuffer && sbuffer) {

	gm_provide_receive_buffer(port, rbuffer, max_size, GM_LOW_PRIORITY);
	gettimeofday(&tv1,0);


	if (*argv[2] != 's'){
	  gm_send_with_callback(port, sbuffer, max_size, our_length,
				GM_LOW_PRIORITY,
				*argv[2]-'0',*argv[1]-'0',
				send_cb,0);
	}

	do{
	  event =  gm_blocking_receive(port);

	  if (GM_RECV_EVENT_TYPE(event) == GM_RECV_EVENT){

		/*
	    printf("got an recv event. length: %d, sender: %d,%d.\n",
		   gm_ntohl(event->recv.length),
		   gm_ntohs(event->recv.sender_node_id),
		   gm_ntohc(event->recv.sender_port_id));
	    memcpy(sbuffer,
		   gm_ntohp(event->recv.buffer),
		   gm_ntohl(event->recv.length));
		*/

	    gm_send_with_callback(port, sbuffer, max_size,
				  gm_ntohl(event->recv.length),
				  GM_LOW_PRIORITY,
				  gm_ntohs(event->recv.sender_node_id),
				  gm_ntohc(event->recv.sender_port_id),
				  send_cb,0);

	    sends++;
	    gm_provide_receive_buffer(port, gm_ntohp(event->recv.buffer),
				      max_size, GM_LOW_PRIORITY);

	    if (sends==max_num_sends) break;

	  } else {
	    gm_unknown(port,event);
	  }
	} while(1);

	gettimeofday(&tv2,0);
	printf("Elapsed usec/send: %ld\n",
	       ((tv2.tv_sec-tv1.tv_sec)*1000000+(tv2.tv_usec-tv1.tv_usec))/max_num_sends);
      }
      else {
	fprintf(stderr, "could not allocate buffer.\n");
      }
    } else {
      fprintf(stderr, "could not open port: %s\n",gm_strerror(status));
    }
    gm_finalize();
    return 0;
  } else {
    fprintf(stderr, "Cannot initialize gm: %s. Aborting.\n",gm_strerror(status));
    return 1;
  }

}
