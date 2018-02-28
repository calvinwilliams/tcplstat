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
#if ( defined __linux__ )
	struct sll_header		*sll = NULL ;
#endif
	struct NetinetEthernetHeader	*etherhdr = NULL ;
	struct NetinetIpHeader		*iphdr = NULL ;
	int				iphdr_size ;
	struct NetinetTcpHeader		*tcphdr = NULL ;
	int				tcphdr_size ;
	unsigned short			ether_type ;
	char				*packet_data_intercepted = NULL ;
	UINT32				packet_data_len_intercepted ;
	
	struct TcplAddrHumanReadable	tcpl_addr_hr ;
	
	int				nret = 0 ;
	
	/* pcap时间戳在虚拟机里有BUG，复制出来修正后再使用 */
	COPY_TIMEVAL( p_env->fixed_timestamp , pcaphdr->ts )
	
	/* Fixed a bug on libpcap */
	if( p_env->fixed_timestamp.tv_sec < 1500000000 )
	{
		COPY_TIMEVAL( p_env->fixed_timestamp , p_env->last_fixed_timestamp )
	}
	
	/* 分析链路层类型 */
	linklayer_header_type = pcap_datalink(p_env->pcap) ;
	switch( linklayer_header_type )
	{
#if ( defined __linux__ )
		case DLT_LINUX_SLL :
			sll = (struct sll_header *)packet ;
			ether_type = ntohs( sll->sll_protocol ) ;
			iphdr = (struct NetinetIpHeader *)( (char*)sll + sizeof(struct sll_header) ) ;
			break;
#endif
		case DLT_NULL :
			ether_type = ETHERTYPE_IP ;
			iphdr = (struct NetinetIpHeader *)( packet + 4 ) ;
			break;
		case DLT_EN10MB :
			etherhdr = (struct NetinetEthernetHeader *)packet ;
			ether_type = ntohs( etherhdr->_ether_type ) ;
			iphdr = (struct NetinetIpHeader *)( (char*)etherhdr + sizeof(struct NetinetEthernetHeader) ) ;
			break;
#if ( defined __linux__ )
		case DLT_RAW :
			ether_type = ETHERTYPE_IP ;
			iphdr = (struct NetinetIpHeader *)( packet ) ;
			break;
#endif
		default :
			fprintf( p_env->fp , "*** WARN : linklayer header type[%d] unknow\n" , linklayer_header_type );
			return;
	}
	
	if( ether_type != ETHERTYPE_IP )
	{
		fprintf( p_env->fp , "*** WARN : ether type[%d] must be ETHERTYPE_IP\n" , ether_type );
		return;
	}
	if( iphdr->_ip_p != IPPROTO_TCP )
	{
		fprintf( p_env->fp , "*** WARN : ip protocol[%d] must be IPPROTO_TCP\n" , iphdr->_ip_p );
		return;
	}
	iphdr_size = IP_HL(iphdr)*4 ;
	tcphdr = (struct NetinetTcpHeader *)( (char*)iphdr + iphdr_size ) ;
	tcphdr_size = TH_OFF(tcphdr)*4 ;
	
	packet_data_len_intercepted = htons(iphdr->_ip_len) - iphdr_size - tcphdr_size ;
	if( packet_data_len_intercepted > 0 )
		packet_data_intercepted = (char*)( (char*)tcphdr + tcphdr_size ) ;
	else
		packet_data_intercepted = NULL ;
	
	/* 转换网络地址信息 */
	memset( & tcpl_addr_hr , 0x00 , sizeof(struct TcplAddrHumanReadable) );
	if( etherhdr )
	{
		sprintf( tcpl_addr_hr.src_mac , "%02X:%02X:%02X:%02X:%02X:%02X" , etherhdr->_ether_shost[0] , etherhdr->_ether_shost[1] , etherhdr->_ether_shost[2] , etherhdr->_ether_shost[3] , etherhdr->_ether_shost[4] , etherhdr->_ether_shost[5] );
		sprintf( tcpl_addr_hr.dst_mac , "%02X:%02X:%02X:%02X:%02X:%02X" , etherhdr->_ether_dhost[0] , etherhdr->_ether_dhost[1] , etherhdr->_ether_dhost[2] , etherhdr->_ether_dhost[3] , etherhdr->_ether_dhost[4] , etherhdr->_ether_dhost[5] );
	}
	strcpy( tcpl_addr_hr.src_ip , inet_ntoa(iphdr->_ip_src) );
	strcpy( tcpl_addr_hr.dst_ip , inet_ntoa(iphdr->_ip_dst) );
	tcpl_addr_hr.src_port = ntohs(tcphdr->_th_sport) ;
	tcpl_addr_hr.dst_port = ntohs(tcphdr->_th_dport) ;
	
	/* 输出事件日志 */
	if( p_env->cmd_line_para.output_event )
	{
		fprintf( p_env->fp , "E | %s.%06ld | LHT[%d] | SMAC[%s] DMAC[%s] | SIP[%s] DIP[%s] | SPORT[%d] DPORT[%d] SEQ[%u] ACK[%u] SYN[%d] ACK[%d] FIN[%d] PSH[%d] RST[%d] URG[%d] | [%d]BYTES\n"
			, ConvDateTimeHumanReadable(p_env->fixed_timestamp.tv_sec) , p_env->fixed_timestamp.tv_usec
			, linklayer_header_type
			, tcpl_addr_hr.src_mac , tcpl_addr_hr.dst_mac
			, tcpl_addr_hr.src_ip , tcpl_addr_hr.dst_ip
			, tcpl_addr_hr.src_port , tcpl_addr_hr.dst_port
			, tcphdr->_th_seq , tcphdr->_th_ack
			, TH_FLAG(tcphdr,TH_SYN) , TH_FLAG(tcphdr,TH_ACK) , TH_FLAG(tcphdr,TH_FIN) , TH_FLAG(tcphdr,TH_PSH) , TH_FLAG(tcphdr,TH_RST) , TH_FLAG(tcphdr,TH_RST)
			, packet_data_len_intercepted );
		
		if( packet_data_len_intercepted > 0 )
		{
			DumpBuffer( p_env->fp , "E |     " , packet_data_len_intercepted , packet_data_intercepted );
		}
	}
	
	/* 处理TCP分组 */
	nret = ProcessTcpPacket( p_env , pcaphdr , etherhdr , iphdr , tcphdr , & tcpl_addr_hr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_intercepted ) ;
	if( nret )
	{
		fprintf( p_env->fp , "*** ERROR : ProcessTcpPacket failed[%d]\n" , nret );
		exit(-nret);
	}
	
	COPY_TIMEVAL( p_env->last_fixed_timestamp , p_env->fixed_timestamp )
	
	return;
}

