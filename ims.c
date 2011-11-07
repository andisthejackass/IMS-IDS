/* ims.c
 *
 * A sniffer adjusted to work with Open-IMS (and any IMS) platform.
 *
 * Version 0.2 (2011-10-09)
 * Author: Andis Anastasis (andisthejackassatgmaildotcom)
 *
 * No copyrights by me, but please read below for the original author's notes
 *
 *
 * NOTE
 * --------
 * This program is to be used with the iptables.sh script in order for
 * the prevention mechanism to work.
 * --------
 *
 ***************************************************************************
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 * 
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and 
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 * 
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 * 
 * "sniffer.c" is distributed under these terms:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 * 
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 * 
 ****************************************************************************
 *
 * Below is an excerpt from an email from Guy Harris on the tcpdump-workers
 * mail list when someone asked, "How do I get the length of the TCP
 * payload?" Guy Harris' slightly snipped response (edited by him to
 * speak of the IPv4 header length and TCP data offset without referring
 * to bitfield structure members) is reproduced below:
 * 
 * The Ethernet size is always 14 bytes.
 * 
 * <snip>...</snip>
 *
 * In fact, you *MUST* assume the Ethernet header is 14 bytes, *and*, if 
 * you're using structures, you must use structures where the members 
 * always have the same size on all platforms, because the sizes of the 
 * fields in Ethernet - and IP, and TCP, and... - headers are defined by 
 * the protocol specification, not by the way a particular platform's C 
 * compiler works.)
 *
 * The IP header size, in bytes, is the value of the IP header length,
 * as extracted from the "ip_vhl" field of "struct sniff_ip" with
 * the "IP_HL()" macro, times 4 ("times 4" because it's in units of
 * 4-byte words).  If that value is less than 20 - i.e., if the value
 * extracted with "IP_HL()" is less than 5 - you have a malformed
 * IP datagram.
 *
 * The TCP header size, in bytes, is the value of the TCP data offset,
 * as extracted from the "th_offx2" field of "struct sniff_tcp" with
 * the "TH_OFF()" macro, times 4 (for the same reason - 4-byte words).
 * If that value is less than 20 - i.e., if the value extracted with
 * "TH_OFF()" is less than 5 - you have a malformed TCP segment.
 *
 * So, to find the IP header in an Ethernet packet, look 14 bytes after 
 * the beginning of the packet data.  To find the TCP header, look 
 * "IP_HL(ip)*4" bytes after the beginning of the IP header.  To find the
 * TCP payload, look "TH_OFF(tcp)*4" bytes after the beginning of the TCP
 * header.
 * 
 * To find out how much payload there is:
 *
 * Take the IP *total* length field - "ip_len" in "struct sniff_ip" 
 * - and, first, check whether it's less than "IP_HL(ip)*4" (after
 * you've checked whether "IP_HL(ip)" is >= 5).  If it is, you have
 * a malformed IP datagram.
 *
 * Otherwise, subtract "IP_HL(ip)*4" from it; that gives you the length
 * of the TCP segment, including the TCP header.  If that's less than
 * "TH_OFF(tcp)*4" (after you've checked whether "TH_OFF(tcp)" is >= 5),
 * you have a malformed TCP segment.
 *
 * Otherwise, subtract "TH_OFF(tcp)*4" from it; that gives you the
 * length of the TCP payload.
 *
 * Note that you also need to make sure that you don't go past the end 
 * of the captured data in the packet - you might, for example, have a 
 * 15-byte Ethernet packet that claims to contain an IP datagram, but if 
 * it's 15 bytes, it has only one byte of Ethernet payload, which is too 
 * small for an IP header.  The length of the captured data is given in 
 * the "caplen" field in the "struct pcap_pkthdr"; it might be less than 
 * the length of the packet, if you're capturing with a snapshot length 
 * other than a value >= the maximum packet size.
 * <end of response>
 * 
 ****************************************************************************
 * 
 * Example compiler command-line for GCC:
 *   gcc -Wall -o sniffex sniffex.c -lpcap
 * 
 ****************************************************************************
 *
 * Code Comments
 *
 * This section contains additional information and explanations regarding
 * comments in the source code. It serves as documentaion and rationale
 * for why the code is written as it is without hindering readability, as it
 * might if it were placed along with the actual code inline. References in
 * the code appear as footnote notation (e.g. [1]).
 *
 * 1. Ethernet headers are always exactly 14 bytes, so we define this
 * explicitly with "#define". Since some compilers might pad structures to a
 * multiple of 4 bytes - some versions of GCC for ARM may do this -
 * "sizeof (struct sniff_ethernet)" isn't used.
 * 
 * 2. Check the link-layer type of the device that's being opened to make
 * sure it's Ethernet, since that's all we handle in this example. Other
 * link-layer types may have different length headers (see [1]).
 *
 * 3. This is the filter expression that tells libpcap which packets we're
 * interested in (i.e. which packets to capture). Since this source example
 * focuses on IP and TCP, we use the expression "ip", so we know we'll only
 * encounter IP packets. The capture filter syntax, along with some
 * examples, is documented in the tcpdump man page under "expression."
 * Below are a few simple examples:
 *
 * Expression			Description
 * ----------			-----------
 * ip					Capture all IP packets.
 * tcp					Capture only TCP packets.
 * tcp port 80			Capture only TCP packets with a port equal to 80.
 * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
 *
 ****************************************************************************
 *
 */

#define APP_NAME		"IMS Sniffer"
#define APP_DESC		"Sniffer for the IMS platform using libpcap"
#define APP_COPYRIGHT	"Andis Anastasis \nUniversity of Piraeus"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>

#include <netinet/if_ether.h>
//#include <net/ethernet.h>
#include <netinet/ether.h>

int coot = 0; //ATJ: metavliti counter gia ton pinaka me ta stoixeia pou theloume
int eidos; //ATJ: metavliti gia na ksexorizoume ta REGISTER apo ta 200 OK paketa
int table_var = 0; //ATJ: metavliti gia tin euresh idou iptables rule

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* UDP header */
struct sniff_udp {
         u_short uh_sport;               /* source port */
         u_short uh_dport;               /* destination port */
         u_short uh_ulen;                /* udp length */
         u_short uh_sum;                 /* udp checksum */

};

#define SIZE_UDP        8               /* length of UDP header */		


void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s \n%s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_udp *udp;            /* The TCP header */
	const char *payload;                    /* Packet payload */
	
	int size_ip;
	int size_udp;
	int size_payload;

	
	//printf("\n####################\n"); --INFO MESSAGE REMOVED--
	//printf("\nPacket number %d:\n", count); --INFO MESSAGE REMOVED--
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	//printf("       From: %s\n", inet_ntoa(ip->ip_src)); --INFO MESSAGE REMOVED--
	//printf("         To: %s\n", inet_ntoa(ip->ip_dst)); --INFO MESSAGE REMOVED--

	const char *dassip = inet_ntoa(ip->ip_dst); //ATJ: metavliti gia tin FROM IP
	


	struct ether_header *eptr;  // ATJ: Domh gia tin mac address 

   
   	eptr = (struct ether_header *) packet;

   	//--INFO MESSAGE REMOVED--fprintf(stdout,"   MAC From: %s\n",
        //--INFO MESSAGE REMOVED--          ether_ntoa((struct ether_addr*)eptr->ether_shost));
  	//--INFO MESSAGE REMOVED--fprintf(stdout,"   MAC   To: %s\n",
              //--INFO MESSAGE REMOVED--    ether_ntoa((struct ether_addr*)eptr->ether_dhost));

	char *s = ether_ntoa((struct ether_addr*)eptr->ether_dhost);
    	char dassmac[30];     //ATJ: H MAC prepei na einai tis morfis 0a:0b:0f kai oxi a:b:f 
   	int a, b, c, d, e, f; //ATJ: alliws den ginetai dekth apo to iptables
    	sscanf(s, "%X:%X:%X:%X:%X:%X", &a, &b, &c, &d, &e, &f);
    	sprintf(dassmac, "%02X:%02X:%02X:%02X:%02X:%02X", a, b, c, d, e, f);

	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			return; //ATJ: return if TCP
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			break;  //ATJ: and break if UDP
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	
	/*
	 *  ATJ: OK, this packet is UDP now...
	 */
	
	/* define/compute tcp header offset */
	
	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + SIZE_UDP);
	
	//--INFO MESSAGE REMOVED--printf("   Src port: %d\n", ntohs(udp->uh_sport));
	//--INFO MESSAGE REMOVED--printf("   Dst port: %d\n", ntohs(udp->uh_dport));
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_UDP);

	char search_for[]="REGISTER"; //ATJ: TERM TO SEARCH IN PAYLOAD
	char search_ok[]="SIP/2.0 200 OK"; //ATJ: string gia na ksexorizoume ta 200 OK paketa
	

	
	if (strstr(payload, search_for)) { //ATJ: if search_for is found in payload, then should print it ;)
	
	/* compute udp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
         if (size_payload > ntohs(udp->uh_ulen))
                 size_payload = ntohs(udp->uh_ulen);
	
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */

	eidos = 1; //ATJ: arxikopoihsh tis metavlitis - otan eidos = 1 shmainei oti to paketo einai REGISTER aplo
	if (strstr(payload, search_ok)) { 

		eidos = 2; //ATJ: an to payload periexei to string "search_ok" tote einai 200 OK minima
	}
	

	if (size_payload > 0) {
		//printf("   Payload (%d bytes):\n", size_payload); //ATJ: comment sto payload size
		//print_payload(payload, size_payload); //ATJ: comment sto "poluploko print"
		//--INFO MESSAGE REMOVED--printf("   Packet Data :\n%s \n", payload); //ATJ: aplo print, mono ta ascii
		  	
			char * pinakas[3][50];  //ATJ: pinakas pou tha krataei ta data poy theloume
			char * tch;		//ATJ: pointer gia to parsing toy payload
			char * saved;		//ATJ: pointer pou sozei kathe fora to segment pou theloume
			char * from;		//ATJ: pointer pou sozei to "From"
			char * contact;		//ATJ: pointer pou sozei to "Contact"
			char * user;		//ATJ: pointer pou sozei to "User"
			char * callid;		//ATJ: pointer pou sozei to "Call-ID" 
			char * table_arr[500];  //ATJ: pinakas pou tha krataei ta iptables rules   
                
			tch = strtok (payload,"<>;\n\"");
			while (tch != NULL)
			{ 
			                
			    if (strncmp(tch, "From",4)==0)    //ATJ:An ta 4 chars tou segment einai "From" tote save  
			    {                                 //to epomeno pou einai to <sip:user@host>
			    tch = strtok (NULL, "<>;\n\"");
				from = tch;                 
				printf ("\n   SIP From: %s \n", from); 
			    }   
			    if (strncmp(tch, "Contact",7)==0) //ATJ: omoiws an ta 7 prwta einai Contact tote 
				{                                  // save to <sip:user@ip>
			    tch = strtok (NULL, "<>;\n\"");
				contact = tch;                 
				printf ("   SIP Cont: %s \n", contact); 
			    } 
			    if (strncmp(tch, "Authorization",13)==0)  //ATJ: Ksana, an to segment ksekinaei me tin   
			    {                              	      // leksi "Authorization" tote save to username
			    tch = strtok (NULL, "<>;\n\"");
				user = tch;                 
				printf ("   SIP User: %s \n", user); 
			    }   
			    if (strncmp(tch, "Call-ID",7)==0)  //ATJ: An ta 7 prota stoixeia tou segment einai "Call-ID" tote to kratame 
			    {                              
				callid = tch;                 
				printf ("    %s \n", callid); 
			    } 
			                            
			    tch = strtok (NULL, "<>;\n\"");

			}
			if ( eidos == 2 ) { //ATJ: ean to paketo einai 200 OK tote ftiaxnoume to arxeio me tous kanones

				int zook; //ATJ: aplos counter
				for (zook = 0; zook < coot; zook++){
					if (callid == pinakas[3][zook] ) { //ATJ: ean to callid uparxei hdh ston pinaka, tote to minima einai authenticated
						/*FILE *file;
						char name[30];
						sprintf(name, "file[%s].rope", callid);//ATJ: dimourgia neou arxeio me different name kathe fora
						file = fopen(name,"a+");
						fprintf(file,"MAC : %s\nIP : %s\nFrom : %s\nContact : %s\nUser : %s\n%s\n\n",dassmac, dassip, pinakas[0][zook], pinakas[1][zook], pinakas[2][zook], pinakas[3][zook]);//ATJ: perasma twn stoixeiwn sto arxeio me tous kanones
						fclose(file); */ //ATJ: uncomment an theloume rules se files
			
		char iptables[200] = "" ; //ATJ: mhdenismos tis metavlitis kathe fora
		sprintf(iptables, "iptables -I INPUT 2 -m mac --mac-source %s -s %s -m string --string \"%s\" --algo bm -j ACCEPT", dassmac, dassip, from); //ATJ: perasma tis entolis stin metavliti iptables



						/*int i = 0;
						int found = 0;
						for ( i ; i < table_var; i++) {
							if ( iptables == table_arr[i] ){
								found = 1;
								printf("\n***RULE ALREADY EXISTS****\n"); }
							}
						printf("\n\n ##### %s #####\n\n",table_arr[i]);
						
						if ( found == 0 ) { */
		system(iptables);//ATJ: ektelesi tis entolis 
							/* table_arr[table_var] = iptables;
							table_var++;
							printf("\n***NEWWWWW****\n"); } */
						

						zook = coot; //ATJ: molis perasei mia fora tous kanones, tote telos
						break;
					}
				}

			    }
			else  { if ((user != NULL)  && (callid != NULL) && (from != NULL) && (contact != NULL)) { //ATJ: ean kanena apo ta stoixeia den einai NULL, tote pername ston pinaka ta dedomena mas
				

				pinakas[0][coot] = from; //ATJ: ekxwrhsh stoixeiwn ston pinaka
				pinakas[1][coot] = contact;
				pinakas[2][coot] = user;
				pinakas[3][coot] = callid; 

				coot++;
					
					
				


				/*int loopa;
				for (loopa = 0; loopa < coot; loopa++){

					printf("\n###%d... - %s - %s - %s - %s --\n", loopa, pinakas[0][loopa],pinakas[1][loopa],pinakas[2][loopa],pinakas[3][loopa]);
					}*/ //ATJ: print tou pinaka - debugging reasons ;)
				
				
				if ( coot == 50 ) { coot = 0; } //ATJ: otan o pinakas ftasei sto 50, mhdenizoume kai pame apo tin arxh
				}}
			 

			 
			}
		}

return;
}





int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "port 4060";	/* filter expression [3] */ //ATJ: 4060 port tou pcscf
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1; 			/* number of packets to capture */
	//ATJ: set to -1 for infite loops of pcap_loop()

	print_app_banner();

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

