/*
 * tcplstat - TCP packets monitor and statistical tool
 * author	: calvin
 * email	: calvinwilliams@163.com
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#include "tcplstat_in.h"

void PcapCallback( u_char *args , const struct pcap_pkthdr *pcaphdr , const u_char *packet )
{
	struct TcplStatEnv		*p_env = (struct TcplStatEnv *)args ;
	struct sll_header		*sll = NULL ;
	struct ether_header		*etherhdr = NULL ;
	struct ip			*iphdr = NULL ;
	int				iphdr_size ;
	struct tcphdr			*tcphdr = NULL ;
	int				tcphdr_size ;
	unsigned short			ether_type ;
	char				*packet_data_intercepted = NULL ;
	uint32_t			packet_data_len_intercepted ;
	
	struct TcplAddrHumanReadable	tcpl_addr_hr ;
	
	int				nret = 0 ;
	
	COPY_TIMEVAL( p_env->fixed_timestamp , pcaphdr->ts )
	
	/* Fixed a bug about pcap */
	if( p_env->fixed_timestamp.tv_sec < 1500000000 )
	{
		COPY_TIMEVAL( p_env->fixed_timestamp , p_env->last_fixed_timestamp )
	}
	
/*
printf( "LIHUA - ts[%ld.%06ld] pcaphdr->len[%d] pcaphdr->caplen[%d] - now[%ld:%06ld]\n" , pcaphdr->ts.tv_sec , pcaphdr->ts.tv_usec , pcaphdr->len , pcaphdr->caplen , p_env->now.tv_sec , p_env->now.tv_usec );
*/
	switch( pcap_datalink(p_env->pcap) )
	{
		case DLT_LINUX_SLL :
			sll = (struct sll_header *)packet ;
			ether_type = ntohs( sll->sll_protocol ) ;
			iphdr = (struct ip *)( (char*)sll + sizeof(struct sll_header) ) ;
			break;
		case DLT_EN10MB :
			etherhdr = (struct ether_header *)packet ;
			ether_type = ntohs( etherhdr->ether_type ) ;
			iphdr = (struct ip *)( (char*)etherhdr + sizeof(struct ether_header) ) ;
			break;
		case DLT_RAW :
			ether_type = ETHERTYPE_IP ;
			iphdr = (struct ip *)( packet ) ;
			break;
		default :
			return;
	}
	
	if( ether_type != ETHERTYPE_IP )
		return;
	if( iphdr->ip_p != IPPROTO_TCP )
		return;
	iphdr_size = iphdr->ip_hl*4 ;
	tcphdr = (struct tcphdr *)( (char*)iphdr + iphdr_size ) ;
	tcphdr_size = tcphdr->doff*4 ;
	
	packet_data_len_intercepted = htons(iphdr->ip_len) - iphdr_size - tcphdr_size ;
	if( packet_data_len_intercepted > 0 )
		packet_data_intercepted = (char*)( (char*)tcphdr + tcphdr_size ) ;
	else
		packet_data_intercepted = NULL ;
	
	strcpy( tcpl_addr_hr.src_ip , inet_ntoa(iphdr->ip_src) );
	strcpy( tcpl_addr_hr.dst_ip , inet_ntoa(iphdr->ip_dst) );
	tcpl_addr_hr.src_port = ntohs(tcphdr->source) ;
	tcpl_addr_hr.dst_port = ntohs(tcphdr->dest) ;
	
#if _TCPLSTAT_DEBUG
	printf( "DEBUG - ETHTYPE[%d] SRCMAC[%X] DSTMAC[%X] | IPID[%d] PROTO[%d] SRCIP[%s] DSTIP[%s] | SRCPORT[%d] DSTPORT[%d] SEQ[%u] ACKSEQ[%u] SYN[%d] ACK[%d] FIN[%d] PSH[%d] RST[%d] URG[%d] | [%d]bytes\n"
		, etherhdr?etherhdr->ether_type:0 , etherhdr?etherhdr->ether_shost[0]:0 , etherhdr?etherhdr->ether_dhost[0]:0
		, iphdr->ip_id , iphdr->ip_p , tcpl_addr_hr.src_ip , tcpl_addr_hr.dst_ip
		, tcpl_addr_hr.src_port , tcpl_addr_hr.dst_port , tcphdr->seq , tcphdr->ack_seq , tcphdr->syn , tcphdr->ack , tcphdr->fin , tcphdr->psh , tcphdr->rst , tcphdr->urg
		, packet_data_len_intercepted );
	DumpBuffer( NULL , "#stdout" , packet_data_len_intercepted , packet_data_intercepted );
#endif
	
	nret = ProcessTcpPacket( p_env , pcaphdr , etherhdr , iphdr , tcphdr , & tcpl_addr_hr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_intercepted ) ;
	if( nret )
	{
		printf( "*** ERROR : ProcessTcpPacket failed[%d]\n" , nret );
		exit(-nret);
	}
	
	COPY_TIMEVAL( p_env->last_fixed_timestamp , p_env->fixed_timestamp )
	
	return;
}

