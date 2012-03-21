#!/usr/bin/gawk -f

# Translate tcpdump output for p4sock:
# tcpdump -l -Xx ether proto 0x0815 or 0x0814 or 0x813 or 0x812
# 2002-10-08 Jens Hauke <hauke@wtal.de>

BEGIN{
 debug=0;
}

function decode(){
 printf "%16s -> %16s ",src, dst;
 if (proto == int("0x814")) {
# typedef struct p4msg_data_header_s{
#    uint16_t	cito;
#    p4_seqno_t	seqno;
#    p4_seqno_t	ackno;
#    p4_seqno_t	winno;
#    uint16_t	len;
#    uint16_t	flags;
#} p4msg_data_header_t;
     printf("DAT cito:%5d seq:%5d ack: %5d win:%5d len:%6d flags:0x%04x",
	    msg[0] + msg[1] *256,
	    msg[2] + msg[3] *256,
	    msg[4] + msg[5] *256,
	    msg[6] + msg[7] *256,
	    msg[8] + msg[9] *256,
	    msg[10] + msg[11] *256);
#     for(i=0;i<20;i+=2) printf("%04x ", msg[2*i] +256*msg[2*i+1]);
 }
 if (proto == int("0x815")) {
#typedef struct p4msg_ack_s{
#    uint16_t	cito;
#    p4_seqno_t	ackno;
#    p4_seqno_t	winsize;
#    uint16_t	resend;
#}p4msg_ack_t;
     printf("ACK cito:%5d ack:%5d           win:%5d resend:%3d",
	    msg[0] + msg[1] *256,
	    msg[2] + msg[3] *256,
	    msg[4] + msg[5] *256,
	    msg[8] + msg[9] *256);
 }
 if (proto == int("0x812")) {
#typedef struct p4msg_syn_s{
#    /* p4prot */
#    uint16_t	cifrom;		/* sender ci_idx */
#    p4_addr_t	destname;	/* remote search for this name and answer with ci_idx */
#    p4_seqno_t	seqno;		/* Initial sequencenumber */
#    /* somtimes communicator dependent data */
#/*    char abc[100];*/
#} p4msg_syn_t;
     printf("SYN cifrom:%5d ... todo",
	    msg[0] + msg[1] *256   );
 }
 if (proto == int("0x813")) {
#typedef struct p4msg_synack_s{
#    /* p4prot */
#    uint16_t	cito;		/* receiver ci_idx */
#    uint16_t	cifrom;		/* sender ci_idx */
#    p4_seqno_t	seqno;		/* Initial sequencenumber */
#    p4_seqno_t	ackno;		/* seqno of SYN message */
#    uint16_t	error;		/* errorcode if syn fails */
#} p4msg_synack_t;
     printf("SYNACK cito:%5d cifrom:%5d seq:%5d ack:%5d error:%5d",
	    msg[0] + msg[1] *256,
	    msg[2] + msg[3] *256,
	    msg[4] + msg[5] *256,
	    msg[6] + msg[7] *256,
	    msg[8] + msg[9] *256);
 }
 printf("\n");
}

/[0-9]+:[0-9]+:[0-9]+.[0-9]+/ {
#    print "MATCH:" $0;

    decode();
    proto=int("0x"$4);
    src=$2;
    dst=$3;
    offset=0;
    next;
}


{
#    print "LINE :" $0;
    for(i=1;i<=8;i++) {
	val = int("0x"$i);
	msg[offset]= int(val/256);
	msg[offset+1]= val - msg[offset] *256;
	offset+=2;
    }
}
