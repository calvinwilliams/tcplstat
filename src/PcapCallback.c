/*
 * tcplstat - TCP packets monitor and statistical tool
 * author	: calvin
 * email	: calvinwilliams@163.com
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#include "tcplstat_in.h"

/* 网络设备嗅探回调函数 */
void PcapCallback( u_char *args , const struct pcap_pkthdr *pcaphdr , const u_char *packet )
{
	struct TcplStatEnv		*p_env = (struct TcplStatEnv *)args ;
	int				linklayer_header_type ;
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
	
	/* pcap时间戳在虚拟机里有BUG，复制出来修正后再使用 */
	COPY_TIMEVAL( p_env->fixed_timestamp , pcaphdr->ts )
	
	/* Fixed a bug about pcap */
	if( p_env->fixed_timestamp.tv_sec < 1500000000 )
	{
		COPY_TIMEVAL( p_env->fixed_timestamp , p_env->last_fixed_timestamp )
	}
	
	/* 分析链路层类型 */
	linklayer_header_type = pcap_datalink(p_env->pcap) ;
	switch( linklayer_header_type )
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
	
	/* 转换网络地址信息 */
	memset( & tcpl_addr_hr , 0x00 , sizeof(struct TcplAddrHumanReadable) );
	if( etherhdr )
	{
		sprintf( tcpl_addr_hr.src_mac , "%02X:%02X:%02X:%02X:%02X:%02X" , etherhdr->ether_shost[0] , etherhdr->ether_shost[1] , etherhdr->ether_shost[2] , etherhdr->ether_shost[3] , etherhdr->ether_shost[4] , etherhdr->ether_shost[5] );
		sprintf( tcpl_addr_hr.dst_mac , "%02X:%02X:%02X:%02X:%02X:%02X" , etherhdr->ether_dhost[0] , etherhdr->ether_dhost[1] , etherhdr->ether_dhost[2] , etherhdr->ether_dhost[3] , etherhdr->ether_dhost[4] , etherhdr->ether_dhost[5] );
	}
	strcpy( tcpl_addr_hr.src_ip , inet_ntoa(iphdr->ip_src) );
	strcpy( tcpl_addr_hr.dst_ip , inet_ntoa(iphdr->ip_dst) );
	tcpl_addr_hr.src_port = ntohs(tcphdr->source) ;
	tcpl_addr_hr.dst_port = ntohs(tcphdr->dest) ;
	
	/* 输出事件日志 */
	if( p_env->cmd_line_para.output_event )
	{
		printf( "E | LHT[%d] | SRCMAC[%s] DSTMAC[%s] | SRCIP[%s] DSTIP[%s] | SRCPORT[%d] DSTPORT[%d] SEQ[%u] ACKSEQ[%u] SYN[%d] ACK[%d] FIN[%d] PSH[%d] RST[%d] URG[%d] | [%d]bytes\n"
			, linklayer_header_type
			, tcpl_addr_hr.src_mac , tcpl_addr_hr.dst_mac
			, tcpl_addr_hr.src_ip , tcpl_addr_hr.dst_ip
			, tcpl_addr_hr.src_port , tcpl_addr_hr.dst_port , tcphdr->seq , tcphdr->ack_seq , tcphdr->syn , tcphdr->ack , tcphdr->fin , tcphdr->psh , tcphdr->rst , tcphdr->urg
			, packet_data_len_intercepted );
		if( packet_data_len_intercepted > 0 )
		{
			DumpBuffer( "E |     " , "#stdout" , packet_data_len_intercepted , packet_data_intercepted );
		}
	}
	
	/* 处理TCP包 */
	nret = ProcessTcpPacket( p_env , pcaphdr , etherhdr , iphdr , tcphdr , & tcpl_addr_hr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_intercepted ) ;
	if( nret )
	{
		printf( "*** ERROR : ProcessTcpPacket failed[%d]\n" , nret );
		exit(-nret);
	}
	
	COPY_TIMEVAL( p_env->last_fixed_timestamp , p_env->fixed_timestamp )
	
	return;
}

