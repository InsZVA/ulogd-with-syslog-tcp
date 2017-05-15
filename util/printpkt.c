/* printpkt.c
 *
 * build something looking like a iptables LOG message
 *
 * (C) 2000-2003 by Harald Welte <laforge@gnumonks.org>
 * (C) 2017-     by InsZVA <inszva@126.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/printpkt.h>
#include <netinet/if_ether.h>
#include <ulogd/speedup.h>

struct ulogd_key printpkt_keys[] = {
	[KEY_OOB_FAMILY]	= { .name = "oob.family", },
	[KEY_OOB_PROTOCOL]	= { .name = "oob.protocol", },
	[KEY_OOB_PREFIX]	= { .name = "oob.prefix", },
	[KEY_OOB_IN]		= { .name = "oob.in", },
	[KEY_OOB_OUT]		= { .name = "oob.out", },
	[KEY_OOB_UID]		= { .name = "oob.uid",
				    .flags = ULOGD_KEYF_OPTIONAL
				  },
	[KEY_OOB_GID]		= { .name = "oob.gid",
				    .flags = ULOGD_KEYF_OPTIONAL
				  },
	[KEY_OOB_MARK]		= { .name = "oob.mark", },
	[KEY_RAW_MAC]		= { .name = "raw.mac", },
	[KEY_RAW_MACLEN]	= { .name = "raw.mac_len", },
	[KEY_IP_SADDR]		= { .name = "ip.saddr.str", },
	[KEY_IP_DADDR]		= { .name = "ip.daddr.str", },
	[KEY_IP_TOTLEN]		= { .name = "ip.totlen", },
	[KEY_IP_TOS]		= { .name = "ip.tos", },
	[KEY_IP_TTL]		= { .name = "ip.ttl", },
	[KEY_IP_ID]		= { .name = "ip.id", },
	[KEY_IP_FRAGOFF]	= { .name = "ip.fragoff", },
	[KEY_IP_PROTOCOL]	= { .name = "ip.protocol", },
	[KEY_IP6_PAYLOAD_LEN]	= { .name = "ip6.payloadlen" },
	[KEY_IP6_PRIORITY]	= { .name = "ip6.priority" },
	[KEY_IP6_HOPLIMIT]	= { .name = "ip6.hoplimit" },
	[KEY_IP6_FLOWLABEL]	= { .name = "ip6.flowlabel" },
	[KEY_IP6_NEXTHDR]	= { .name = "ip6.nexthdr" },
	[KEY_IP6_FRAG_OFF]	= { .name = "ip6.fragoff" },
	[KEY_IP6_FRAG_ID]	= { .name = "ip6.fragid" },
	[KEY_TCP_SPORT]		= { .name = "tcp.sport", },
	[KEY_TCP_DPORT]		= { .name = "tcp.dport", },
	[KEY_TCP_SEQ]		= { .name = "tcp.seq", },
	[KEY_TCP_ACKSEQ]	= { .name = "tcp.ackseq", },
	[KEY_TCP_WINDOW]	= { .name = "tcp.window", },
	[KEY_TCP_SYN]		= { .name = "tcp.syn", },
	[KEY_TCP_ACK]		= { .name = "tcp.ack", },
	[KEY_TCP_PSH]		= { .name = "tcp.psh", },
	[KEY_TCP_RST]		= { .name = "tcp.rst", },
	[KEY_TCP_FIN]		= { .name = "tcp.fin", },
	[KEY_TCP_URG]		= { .name = "tcp.urg", },
	[KEY_TCP_URGP]		= { .name = "tcp.urgp", },
	[KEY_UDP_SPORT]		= { .name = "udp.sport", },
	[KEY_UDP_DPORT]		= { .name = "udp.dport", },
	[KEY_UDP_LEN]		= { .name = "udp.len", },
	[KEY_ICMP_TYPE]		= { .name = "icmp.type", },
	[KEY_ICMP_CODE]		= { .name = "icmp.code", },
	[KEY_ICMP_ECHOID]	= { .name = "icmp.echoid", },
	[KEY_ICMP_ECHOSEQ]	= { .name = "icmp.echoseq", },
	[KEY_ICMP_GATEWAY]	= { .name = "icmp.gateway", },
	[KEY_ICMP_FRAGMTU]	= { .name = "icmp.fragmtu", },
	[KEY_ICMPV6_TYPE]	= { .name = "icmpv6.type", },
	[KEY_ICMPV6_CODE]	= { .name = "icmpv6.code", },
	[KEY_ICMPV6_ECHOID]	= { .name = "icmpv6.echoid", },
	[KEY_ICMPV6_ECHOSEQ]	= { .name = "icmpv6.echoseq", },
	[KEY_AHESP_SPI]		= { .name = "ahesp.spi", },
	[KEY_ARP_HTYPE]         = { .name = "arp.hwtype", },
	[KEY_ARP_PTYPE]         = { .name = "arp.protocoltype", },
	[KEY_ARP_OPCODE]        = { .name = "arp.operation", },
	[KEY_ARP_SHA]           = { .name = "arp.shwaddr", },
	[KEY_ARP_SPA]           = { .name = "arp.saddr.str", },
	[KEY_ARP_THA]           = { .name = "arp.dhwaddr", },
	[KEY_ARP_TPA]           = { .name = "arp.daddr.str", },
	[KEY_SCTP_SPORT]	= { .name = "sctp.sport", },
	[KEY_SCTP_DPORT]	= { .name = "sctp.dport", },
};


static int printpkt_proto(struct ulogd_key *res, char *buf, int protocol)
{
	char *buf_cur = buf;

	switch (protocol) {
	case IPPROTO_TCP:
		//buf_cur += sprintf(buf_cur, "PROTO=TCP ");
		appendStr(&buf_cur, "PROTO=TCP ");

		if (!pp_is_valid(res, KEY_TCP_SPORT)) {
			//buf_cur += sprintf(buf_cur, "INCOMPLETE");
			appendStr(&buf_cur, "INCOMPLETE");
			break;
		}

		//buf_cur += sprintf(buf_cur, "SPT=%u DPT=%u ",
				   //ikey_get_u16(&res[KEY_TCP_SPORT]),
				   //ikey_get_u16(&res[KEY_TCP_DPORT]));
		appendStr(&buf_cur, "SPT=");
		appendUint(&buf_cur, ikey_get_u16(&res[KEY_TCP_SPORT]));
		appendStr(&buf_cur, " DPT=");
		appendUint(&buf_cur, ikey_get_u16(&res[KEY_TCP_DPORT]));
		
		/* FIXME: config */
		//buf_cur += sprintf(buf_cur, "SEQ=%u ACK=%u ",
				   //ikey_get_u32(&res[KEY_TCP_SEQ]),
				   //ikey_get_u32(&res[KEY_TCP_ACKSEQ]));
		appendStr(&buf_cur, " SEQ=");
		appendUint(&buf_cur, ikey_get_u32(&res[KEY_TCP_SEQ]));
		appendStr(&buf_cur, " ACK=");
		appendUint(&buf_cur, ikey_get_u32(&res[KEY_TCP_ACKSEQ]));

		//buf_cur += sprintf(buf_cur, "WINDOW=%u ",
				   //ikey_get_u16(&res[KEY_TCP_WINDOW]));
		appendStr(&buf_cur, " WINDOW=");
		appendUint(&buf_cur, ikey_get_u16(&res[KEY_TCP_WINDOW]));
		appendStr(&buf_cur, " ");

//		buf_cur += sprintf(buf_cur, "RES=0x%02x ", 
		
		if (ikey_get_u8(&res[KEY_TCP_URG]))
			//buf_cur += sprintf(buf_cur, "URG ");
			appendStr(&buf_cur, "URG ");

		if (ikey_get_u8(&res[KEY_TCP_ACK]))
			//buf_cur += sprintf(buf_cur, "ACK ");
			appendStr(&buf_cur, "ACK ");

		if (ikey_get_u8(&res[KEY_TCP_PSH]))
			//buf_cur += sprintf(buf_cur, "PSH ");
			appendStr(&buf_cur, "PSH ");

		if (ikey_get_u8(&res[KEY_TCP_RST]))
			//buf_cur += sprintf(buf_cur, "RST ");
			appendStr(&buf_cur, "RST ");

		if (ikey_get_u8(&res[KEY_TCP_SYN]))
			//buf_cur += sprintf(buf_cur, "SYN ");
			appendStr(&buf_cur, "SYN ");

		if (ikey_get_u8(&res[KEY_TCP_FIN]))
			//buf_cur += sprintf(buf_cur, "FIN ");
			appendStr(&buf_cur, "FIN ");

		//buf_cur += sprintf(buf_cur, "URGP=%u ",
				   //ikey_get_u16(&res[KEY_TCP_URGP]));
		appendStr(&buf_cur, "URGP=");
		appendUint(&buf_cur, ikey_get_u16(&res[KEY_TCP_URGP]));
		appendStr(&buf_cur, " ");

		break;

	case IPPROTO_UDP:
		//buf_cur += sprintf(buf_cur, "PROTO=UDP ");
		appendStr(&buf_cur, "PROTO=UDP ");

		if (!pp_is_valid(res, KEY_UDP_SPORT)) {
			//buf_cur += sprintf(buf_cur, "INCOMPLETE");
			appendStr(&buf_cur, "INCOMPLETE");
			break;
		}

		//buf_cur += sprintf(buf_cur, "SPT=%u DPT=%u LEN=%u ", 
				   //ikey_get_u16(&res[KEY_UDP_SPORT]),
				   //ikey_get_u16(&res[KEY_UDP_DPORT]), 
				   //ikey_get_u16(&res[KEY_UDP_LEN]));
		appendStr(&buf_cur, "SPT=");
		appendUint(&buf_cur, ikey_get_u16(&res[KEY_UDP_SPORT]));
		appendStr(&buf_cur, " DPT=");
		appendUint(&buf_cur, ikey_get_u16(&res[KEY_UDP_DPORT]));
		appendStr(&buf_cur, " LEN=");
		appendUint(&buf_cur, ikey_get_u16(&res[KEY_UDP_LEN]));
		appendStr(&buf_cur, " ");
		break;
	case IPPROTO_SCTP:
		//buf_cur += sprintf(buf_cur, "PROTO=SCTP ");
		appendStr(&buf_cur, "PROTO=SCTP ");

		if (!pp_is_valid(res, KEY_SCTP_SPORT)) {
			//buf_cur += sprintf(buf_cur, "INCOMPLETE");
			appendStr(&buf_cur, "INCOMPLETE");
			break;
		}

		//buf_cur += sprintf(buf_cur, "SPT=%u DPT=%u ", 
				   //ikey_get_u16(&res[KEY_SCTP_SPORT]),
				   //ikey_get_u16(&res[KEY_SCTP_DPORT]));
		appendStr(&buf_cur, "SPT=");
		appendUint(&buf_cur, ikey_get_u16(&res[KEY_SCTP_SPORT]));
		appendStr(&buf_cur, " DPT=");
		appendUint(&buf_cur, ikey_get_u16(&res[KEY_SCTP_DPORT]));
		appendStr(&buf_cur, " ");
		break;
	case IPPROTO_ESP:
	case IPPROTO_AH:
		//buf_cur += sprintf(buf_cur, "PROTO=%s ",
				   //ikey_get_u8(&res[KEY_IP_PROTOCOL]) == IPPROTO_ESP ? "ESP" : "AH");
		appendStr(&buf_cur, "PROTO=");
		appendStr(&buf_cur, ikey_get_u8(&res[KEY_IP_PROTOCOL]) == IPPROTO_ESP ? "ESP " : "AH ");

		if (!pp_is_valid(res, KEY_AHESP_SPI)) {
			//buf_cur += sprintf(buf_cur, "INCOMPLETE");
			appendStr(&buf_cur, "INCOMPLETE");
			break;
		}

		//buf_cur += sprintf(buf_cur, "SPI=0x%x ",
				   //ikey_get_u32(&res[KEY_AHESP_SPI]));
		appendStr(&buf_cur, "SPI=0x");
		appendHex(&buf_cur, ikey_get_u32(&res[KEY_AHESP_SPI]));
		appendStr(&buf_cur, " ");
		break;
	}

	return buf_cur - buf;
}

static int printpkt_ipv4(struct ulogd_key *res, char *buf)
{
	char *buf_cur = buf;
	char tmp[INET_ADDRSTRLEN];
	u_int32_t paddr;
	char *ipstr = 0;

	if (pp_is_valid(res, KEY_IP_SADDR)) {
		//buf_cur += sprintf(buf_cur, "SRC=%s ",
				   //(char *) ikey_get_ptr(&res[KEY_IP_SADDR]));
		appendStr(&buf_cur, "SRC=");
		appendStr(&buf_cur, (char*) ikey_get_ptr(&res[KEY_IP_SADDR]));
		appendStr(&buf_cur, " ");
	}

	if (pp_is_valid(res, KEY_IP_DADDR)) {
		//buf_cur += sprintf(buf_cur, "DST=%s ",
				   //(char *) ikey_get_ptr(&res[KEY_IP_DADDR]));
		appendStr(&buf_cur, "DST=");
		appendStr(&buf_cur, (char*) ikey_get_ptr(&res[KEY_IP_DADDR]));
		appendStr(&buf_cur, " ");
	}

	/* FIXME: add pp_is_valid calls to remainder of file */
	//buf_cur += sprintf(buf_cur,"LEN=%u TOS=%02X PREC=0x%02X TTL=%u ID=%u ", 
			   //ikey_get_u16(&res[KEY_IP_TOTLEN]),
			   //ikey_get_u8(&res[KEY_IP_TOS]) & IPTOS_TOS_MASK, 
			   //ikey_get_u8(&res[KEY_IP_TOS]) & IPTOS_PREC_MASK,
			   //ikey_get_u8(&res[KEY_IP_TTL]),
			   //ikey_get_u16(&res[KEY_IP_ID]));
	appendStr(&buf_cur, "LEN=");
	appendUint(&buf_cur, ikey_get_u16(&res[KEY_IP_TOTLEN]));
	appendStr(&buf_cur, " TOS=");
	appendHEX2(&buf_cur, ikey_get_u8(&res[KEY_IP_TOS]) & IPTOS_TOS_MASK);
	appendStr(&buf_cur, " PREC=0x");
	appendHEX2(&buf_cur, ikey_get_u8(&res[KEY_IP_TOS]) & IPTOS_PREC_MASK);
	appendStr(&buf_cur, " TTL=");
	appendUint(&buf_cur, ikey_get_u8(&res[KEY_IP_TTL]));
	appendStr(&buf_cur, " ID=");
	appendUint(&buf_cur, ikey_get_u16(&res[KEY_IP_ID]));
	appendStr(&buf_cur, " ");

	if (ikey_get_u16(&res[KEY_IP_FRAGOFF]) & IP_RF) 
		//buf_cur += sprintf(buf_cur, "CE ");
		appendStr(&buf_cur, "CE ");

	if (ikey_get_u16(&res[KEY_IP_FRAGOFF]) & IP_DF)
		//buf_cur += sprintf(buf_cur, "DF ");
		appendStr(&buf_cur, "DF ");

	if (ikey_get_u16(&res[KEY_IP_FRAGOFF]) & IP_MF)
		//buf_cur += sprintf(buf_cur, "MF ");
		appendStr(&buf_cur, "MF ");

	if (ikey_get_u16(&res[KEY_IP_FRAGOFF]) & IP_OFFMASK) {
		//buf_cur += sprintf(buf_cur, "FRAG:%u ", 
				   //ikey_get_u16(&res[KEY_IP_FRAGOFF]) & IP_OFFMASK);
		appendStr(&buf_cur, "FRAG:");
		appendUint(&buf_cur, ikey_get_u16(&res[KEY_IP_FRAGOFF]) & IP_OFFMASK);
		appendStr(&buf_cur, " ");
	}

	switch (ikey_get_u8(&res[KEY_IP_PROTOCOL])) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
	case IPPROTO_ESP:
	case IPPROTO_AH:
		buf_cur += printpkt_proto(res, buf_cur,
					  ikey_get_u8(&res[KEY_IP_PROTOCOL]));
		break;

	case IPPROTO_ICMP:
		//buf_cur += sprintf(buf_cur, "PROTO=ICMP ");
		appendStr(&buf_cur, "PROTO=ICMP ");

		if (!pp_is_valid(res, KEY_ICMP_TYPE)) {
			//buf_cur += sprintf(buf_cur, "INCOMPLETE");
			appendStr(&buf_cur, "INCOMPLETE");
			break;
		}

		//buf_cur += sprintf(buf_cur, "TYPE=%u CODE=%u ",
				   //ikey_get_u8(&res[KEY_ICMP_TYPE]),
				   //ikey_get_u8(&res[KEY_ICMP_CODE]));
		appendStr(&buf_cur, "TYPE=");
		appendUint(&buf_cur, ikey_get_u8(&res[KEY_ICMP_TYPE]));
		appendStr(&buf_cur, " CODE=");
		appendUint(&buf_cur, ikey_get_u8(&res[KEY_ICMP_CODE]));
		appendStr(&buf_cur, " ");

		switch (ikey_get_u8(&res[KEY_ICMP_CODE])) {
		case ICMP_ECHO:
		case ICMP_ECHOREPLY:
			//buf_cur += sprintf(buf_cur, "ID=%u SEQ=%u ", 
					   //ikey_get_u16(&res[KEY_ICMP_ECHOID]),
					   //ikey_get_u16(&res[KEY_ICMP_ECHOSEQ]));
			appendStr(&buf_cur, "ID=");
			appendUint(&buf_cur, ikey_get_u16(&res[KEY_ICMP_ECHOID]));
			appendStr(&buf_cur, " SEQ=");
			appendUint(&buf_cur, ikey_get_u16(&res[KEY_ICMP_ECHOSEQ]));
			appendStr(&buf_cur, " ");
			break;
		case ICMP_PARAMETERPROB:
			//buf_cur += sprintf(buf_cur, "PARAMETER=%u ",
					   //ikey_get_u32(&res[KEY_ICMP_GATEWAY]) >> 24);
			appendStr(&buf_cur, "PARAMETER=");
			appendUint(&buf_cur, ikey_get_u32(&res[KEY_ICMP_GATEWAY]) >> 24);
			appendStr(&buf_cur, " ");
			break;
		case ICMP_REDIRECT:
			paddr = ikey_get_u32(&res[KEY_ICMP_GATEWAY]),
			//buf_cur += sprintf(buf_cur, "GATEWAY=%s ",
					   //inet_ntop(AF_INET,
						     //&paddr,
						     //tmp, sizeof(tmp)));
			appendStr(&buf_cur, "GATEWAY=");
			ipstr = inet_ntop(AF_INET, &paddr, tmp, sizeof(tmp));
			appendStr(&buf_cur, ipstr);
			break;
		case ICMP_DEST_UNREACH:
			if (ikey_get_u8(&res[KEY_ICMP_CODE]) == ICMP_FRAG_NEEDED) {
				//buf_cur += sprintf(buf_cur, "MTU=%u ", 
						   //ikey_get_u16(&res[KEY_ICMP_FRAGMTU]));
				appendStr(&buf_cur, "MTU=");
				appendUint(&buf_cur, ikey_get_u16(&res[KEY_ICMP_FRAGMTU]));
				appendStr(&buf_cur, " ");
			}
			break;
		}
		break;
	default:
		//buf_cur += sprintf(buf_cur, "PROTO=%u ",
				   //ikey_get_u8(&res[KEY_IP_PROTOCOL]));
		appendStr(&buf_cur, "PROTO=");
		appendUint(&buf_cur, ikey_get_u8(&res[KEY_IP_PROTOCOL]));
		appendStr(&buf_cur, " ");
	}

	return buf_cur - buf;
}

static int printpkt_ipv6(struct ulogd_key *res, char *buf)
{
	char *buf_cur = buf;

	if (pp_is_valid(res, KEY_IP_SADDR)) {
		//buf_cur += sprintf(buf_cur, "SRC=%s ",
				   //(char *) ikey_get_ptr(&res[KEY_IP_SADDR]));
		appendStr(&buf_cur, "SRC=");
		appendStr(&buf_cur, (char*) ikey_get_ptr(&res[KEY_IP_SADDR]));
	}

	if (pp_is_valid(res, KEY_IP_DADDR)) {
		//buf_cur += sprintf(buf_cur, "DST=%s ",
				   //(char *) ikey_get_ptr(&res[KEY_IP_SADDR]));
		appendStr(&buf_cur, "DST=");
		appendStr(&buf_cur, (char*) ikey_get_ptr(&res[KEY_IP_DADDR]));
	}

	if (pp_is_valid(res, KEY_IP6_PAYLOAD_LEN)) {
		//buf_cur += sprintf(buf_cur, "LEN=%zu ",
				   //ikey_get_u16(&res[KEY_IP6_PAYLOAD_LEN]) +
				   //sizeof(struct ip6_hdr));
		appendStr(&buf_cur, "LEN=");
		appendUint(&buf_cur, ikey_get_u16(&res[KEY_IP6_PAYLOAD_LEN]) + sizeof(struct ip6_hdr));
		appendStr(&buf_cur, " ");
	}

	if (pp_is_valid(res, KEY_IP6_PRIORITY)) {
		//buf_cur += sprintf(buf_cur, "TC=%u ",
				   //ikey_get_u8(&res[KEY_IP6_PRIORITY]));
		appendStr(&buf_cur, "TC=");
		appendUint(&buf_cur, ikey_get_u8(&res[KEY_IP6_PRIORITY]));
		appendStr(&buf_cur, " ");
	}

	if (pp_is_valid(res, KEY_IP6_HOPLIMIT)) {
		//buf_cur += sprintf(buf_cur, "HOPLIMIT=%u ",
				   //ikey_get_u8(&res[KEY_IP6_HOPLIMIT]));
		appendStr(&buf_cur, "HOPLIMIT=");
		appendUint(&buf_cur, ikey_get_u8(&res[KEY_IP6_HOPLIMIT]));
		appendStr(&buf_cur, " ");
	}
	
	if (pp_is_valid(res, KEY_IP6_FLOWLABEL)) {
		//buf_cur += sprintf(buf_cur, "FLOWLBL=%u ",
				   //ikey_get_u32(&res[KEY_IP6_FLOWLABEL]));
		appendStr(&buf_cur, "FLOWLBL=");
		appendUint(&buf_cur, ikey_get_u8(&res[KEY_IP6_FLOWLABEL]));
		appendStr(&buf_cur, " ");
	}

	if (pp_is_valid(res, KEY_IP6_FRAG_OFF) && pp_is_valid(res, KEY_IP6_FRAG_ID)) {
		//buf_cur += sprintf(buf_cur, "FRAG: %u ID: %08x ",
				   //ikey_get_u16(&res[KEY_IP6_FRAG_OFF]),
				   //ikey_get_u32(&res[KEY_IP6_FRAG_ID]));
		appendStr(&buf_cur, "FRAG: ");
		appendUint(&buf_cur, ikey_get_u16(&res[KEY_IP6_FRAG_OFF]));
		appendStr(&buf_cur, " ID: ");
		appendHex8(&buf_cur, ikey_get_u32(&res[KEY_IP6_FRAG_ID]));
		appendStr(&buf_cur, " ");
	}

	switch (ikey_get_u8(&res[KEY_IP6_NEXTHDR])) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
	case IPPROTO_ESP:
	case IPPROTO_AH:
		buf_cur += printpkt_proto(res, buf_cur,
					  ikey_get_u8(&res[KEY_IP6_NEXTHDR]));
		break;
	case IPPROTO_ICMPV6:
		//buf_cur += sprintf(buf_cur, "PROTO=ICMPv6 ");
		appendStr(&buf_cur, "PROTO=ICMPv6 ");

		if (!pp_is_valid(res, KEY_ICMPV6_TYPE)) {
			//buf_cur += sprintf(buf_cur, "INCOMPLETE");
			appendStr(&buf_cur, "INCOMPLETE");
			break;
		}

		if (!(pp_is_valid(res, KEY_ICMPV6_TYPE) &&
		      pp_is_valid(res, KEY_ICMPV6_CODE))) {
			//buf_cur += sprintf(buf_cur, "TRUNCATED");
			appendStr(&buf_cur, "TRUNCATED");
			break;
		}

		//buf_cur += sprintf(buf_cur, "TYPE=%u CODE=%u ",
				   //ikey_get_u8(&res[KEY_ICMPV6_TYPE]),
				   //ikey_get_u8(&res[KEY_ICMPV6_CODE]));
		appendStr(&buf_cur, "TYPE=");
		appendUint(&buf_cur, ikey_get_u8(&res[KEY_ICMPV6_TYPE]));
		appendStr(&buf_cur, " CODE=");
		appendUint(&buf_cur, ikey_get_u8(&res[KEY_ICMPV6_CODE]));
		appendStr(&buf_cur, " ");

		switch (ikey_get_u8(&res[KEY_ICMPV6_TYPE])) {
		case ICMP6_ECHO_REQUEST:
		case ICMP6_ECHO_REPLY:
			//buf_cur += sprintf(buf_cur, "ID=%u SEQ=%u ", 
					   //ikey_get_u16(&res[KEY_ICMPV6_ECHOID]),
					   //ikey_get_u16(&res[KEY_ICMPV6_ECHOSEQ]));
			appendStr(&buf_cur, "ID=");
			appendUint(&buf_cur, ikey_get_u16(&res[KEY_ICMPV6_ECHOID]));
			appendStr(&buf_cur, " SEQ=");
			appendUint(&buf_cur, ikey_get_u16(&res[KEY_ICMPV6_ECHOSEQ]));
			appendStr(&buf_cur, " ");
			break;
		}
		break;
	}

	return buf_cur - buf;
}

int printpkt_arp(struct ulogd_key *res, char *buf)
{
	int i;
	char *buf_cur = buf;
	u_int16_t code = 0;
	u_int8_t *mac;

	if (pp_is_valid(res, KEY_ARP_SPA)) {
		//buf_cur += sprintf(buf_cur, "SRC=%s ",
				   //(char *) ikey_get_ptr(&res[KEY_ARP_SPA]));
		appendStr(&buf_cur, "SRC=");
		appendStr(&buf_cur, (char*) ikey_get_ptr(&res[KEY_ARP_SPA]));
		appendStr(&buf_cur, " ");
	}

	if (pp_is_valid(res, KEY_ARP_TPA)) {
		//buf_cur += sprintf(buf_cur, "DST=%s ",
				   //(char *) ikey_get_ptr(&res[KEY_ARP_TPA]));
		appendStr(&buf_cur, "DST=");
		appendStr(&buf_cur, (char *) ikey_get_ptr(&res[KEY_ARP_TPA]));
	}

	//buf_cur += sprintf(buf_cur, "PROTO=ARP ");
	appendStr(&buf_cur, "PROTO=ARP");
	
	if (pp_is_valid(res, KEY_ARP_OPCODE)) {
		code = ikey_get_u16(&res[KEY_ARP_OPCODE]);
		switch (code) {
		case ARPOP_REQUEST:
			//buf_cur += sprintf(buf_cur, "REQUEST ");
			appendStr(&buf_cur, "REQUEST ");
			break;
		case ARPOP_REPLY:
			//buf_cur += sprintf(buf_cur, "REPLY ");
			appendStr(&buf_cur, "REPLY ");
			break;
		case ARPOP_NAK:
			//buf_cur += sprintf(buf_cur, "NAK ");
			appendStr(&buf_cur, "NAK ");
			break;
		default:
			//buf_cur += sprintf(buf_cur, "CODE=%u ", code);
			appendStr(&buf_cur, "CODE=");
			appendUint(&buf_cur, code);
			appendStr(&buf_cur, " ");
		}

		if (pp_is_valid(res, KEY_ARP_SHA) && (code == ARPOP_REPLY)) {
			mac = ikey_get_ptr(&res[KEY_ARP_SHA]);
			//buf_cur += sprintf(buf_cur, "REPLY_MAC="
					   //"%02x:%02x:%02x:%02x:%02x:%02x ",
					   //mac[0], mac[1], mac[2],
					   //mac[3], mac[4], mac[5]);
			appendStr(&buf_cur, "REPLY_MAC=");
			for (i = 0; i < 5; i++) {
				appendHex2(&buf_cur, mac[i]);
				appendStr(&buf_cur, ":");
			}
			appendHex2(&buf_cur, mac[5]);
		}
	}

	return buf_cur - buf;
}


int printpkt_bridge(struct ulogd_key *res, char *buf)
{
	char *buf_cur = buf;

	switch (ikey_get_u16(&res[KEY_OOB_PROTOCOL])) {
	case ETH_P_IP:
		buf_cur += printpkt_ipv4(res, buf_cur);
		break;
	case ETH_P_IPV6:
		buf_cur += printpkt_ipv6(res, buf_cur);
		break;
	case ETH_P_ARP:
		buf_cur += printpkt_arp(res, buf_cur);
		break;
	default:
		//buf_cur += sprintf(buf_cur, "PROTO=%u ",
				   //ikey_get_u16(&res[KEY_OOB_PROTOCOL]));
		appendStr(&buf_cur, "PROTO=");
		appendUint(&buf_cur, ikey_get_u16(&res[KEY_OOB_PROTOCOL]));
		appendStr(&buf_cur, " ");
	}

	return buf_cur - buf;
}

int printpkt_print(struct ulogd_key *res, char *buf)
{
	char *buf_cur = buf;

	if (pp_is_valid(res, KEY_OOB_PREFIX)) {
		//buf_cur += sprintf(buf_cur, "%s ",
				   //(char *) ikey_get_ptr(&res[KEY_OOB_PREFIX]));
		appendStr(&buf_cur, (char *) ikey_get_ptr(&res[KEY_OOB_PREFIX]));
		appendStr(&buf_cur, " ");
	}

	if (pp_is_valid(res, KEY_OOB_IN) && pp_is_valid(res, KEY_OOB_OUT)) {
		//buf_cur += sprintf(buf_cur, "IN=%s OUT=%s ", 
				   //(char *) ikey_get_ptr(&res[KEY_OOB_IN]), 
				   //(char *) ikey_get_ptr(&res[KEY_OOB_OUT]));
		appendStr(&buf_cur, "IN=");
		appendStr(&buf_cur, (char *) ikey_get_ptr(&res[KEY_OOB_IN]));
		appendStr(&buf_cur, " OUT=");
		appendStr(&buf_cur, (char *) ikey_get_ptr(&res[KEY_OOB_OUT]));
		appendStr(&buf_cur, " ");
	}

	/* FIXME: configurable */
	if (pp_is_valid(res, KEY_RAW_MAC)) {
		unsigned char *mac = (unsigned char *) ikey_get_ptr(&res[KEY_RAW_MAC]);
		int i, len = ikey_get_u16(&res[KEY_RAW_MACLEN]);

		//buf_cur += sprintf(buf_cur, "MAC=");
		appendStr(&buf_cur, "MAC=");
		for (i = 0; i < len; i++) {
			//buf_cur += sprintf(buf_cur, "%02x%c", mac[i],
					   //i == len - 1 ? ' ' : ':');
			appendHex2(&buf_cur, mac[i]);
			appendStr(&buf_cur, i == len - 1 ? " " : ":");
		}
	} else
		//buf_cur += sprintf(buf_cur, "MAC= ");
		appendStr(&buf_cur, "MAC= ");

	switch (ikey_get_u8(&res[KEY_OOB_FAMILY])) {
	case AF_INET:
		buf_cur += printpkt_ipv4(res, buf_cur);
		break;
	case AF_INET6:
		buf_cur += printpkt_ipv6(res, buf_cur);
		break;
	case AF_BRIDGE:
		buf_cur += printpkt_bridge(res, buf_cur);
		break;
	}

	if (pp_is_valid(res, KEY_OOB_UID)) {
		//buf_cur += sprintf(buf_cur, "UID=%u ",
				   //ikey_get_u32(&res[KEY_OOB_UID]));
		appendStr(&buf_cur, "UID=");
		appendUint(&buf_cur, ikey_get_u32(&res[KEY_OOB_UID]));
		appendStr(&buf_cur, " ");
	}
	
	if (pp_is_valid(res, KEY_OOB_GID)) {
		//buf_cur += sprintf(buf_cur, "GID=%u ",
				   //ikey_get_u32(&res[KEY_OOB_GID]));
		appendStr(&buf_cur, "GUID=");
		appendUint(&buf_cur, ikey_get_u32(&res[KEY_OOB_GID]));
		appendStr(&buf_cur, " ");
	}
	
	if (pp_is_valid(res, KEY_OOB_MARK)) {
		//buf_cur += sprintf(buf_cur, "MARK=%x ",
				   //ikey_get_u32(&res[KEY_OOB_MARK]));
		appendStr(&buf_cur, "MARK=");
		appendHex(&buf_cur, ikey_get_u32(&res[KEY_OOB_MARK]));
		appendStr(&buf_cur, " ");
	}

	strcat(buf_cur, "\n");

	return 0;
}

