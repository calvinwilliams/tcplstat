#include "tcplstat_in.h"

void PcapCallback( u_char *args , const struct pcap_pkthdr *pcaphdr , const u_char *packet )
{
	struct TcplStatEnv		*p_env = (struct TcplStatEnv *)args ;
	struct sll_header		*sll = NULL ;
	struct ether_header		*etherhdr = NULL ;
	struct ip			*iphdr = NULL ;
	struct tcphdr			*tcphdr = NULL ;
	unsigned short			type ;
	char				*packet_data = NULL ;
	uint32_t			packet_data_len ;
	
	struct TcplAddrHumanReadable	tcpl_addr_hr ;
	
	int				nret = 0 ;
	
	switch( pcap_datalink(p_env->pcap) )
	{
		case DLT_LINUX_SLL :
			sll = (struct sll_header *)packet ;
			type = ntohs( sll->sll_protocol ) ;
			iphdr = (struct ip *)( (char*)sll + sizeof(struct sll_header) ) ;
			break;
		case DLT_EN10MB :
			etherhdr = (struct ether_header *)packet ;
			type = ntohs( etherhdr->ether_type ) ;
			iphdr = (struct ip *)( (char*)etherhdr + sizeof(struct ether_header) ) ;
			break;
		case DLT_RAW :
			type = ETHERTYPE_IP ;
			iphdr = (struct ip *)( packet ) ;
			break;
		default :
			return;
	}
	
	if( type != ETHERTYPE_IP )
		return;
	
	tcphdr = (struct tcphdr *)( (char*)iphdr + iphdr->ip_hl * 4 ) ;
	
	packet_data_len = htons(iphdr->ip_len) - sizeof(struct ip) - tcphdr->doff * 4 ;
	packet_data = (char*)( (char*)tcphdr + tcphdr->doff * 4 ) ;
	
	strcpy( tcpl_addr_hr.src_ip , inet_ntoa(iphdr->ip_src) );
	strcpy( tcpl_addr_hr.dst_ip , inet_ntoa(iphdr->ip_dst) );
	tcpl_addr_hr.src_port = ntohs(tcphdr->source) ;
	tcpl_addr_hr.dst_port = ntohs(tcphdr->dest) ;
	
#if _DEBUG
	printf( "DEBUG - ETHTYPE[%d] SRCMAC[%X] DSTMAC[%X] | IPID[%d] PROTO[%d] SRCIP[%s] DSTIP[%s] | SRCPORT[%d] DSTPORT[%d] SEQ[%u] ACKSEQ[%u] SYN[%d] ACK[%d] FIN[%d] PSH[%d] RST[%d] URG[%d] | [%d]bytes\n"
		, etherhdr?etherhdr->ether_type:0 , etherhdr?etherhdr->ether_shost[0]:0 , etherhdr?etherhdr->ether_dhost[0]:0
		, iphdr->ip_id , iphdr->ip_p , tcpl_addr_hr.src_ip , tcpl_addr_hr.dst_ip
		, tcpl_addr_hr.src_port , tcpl_addr_hr.dst_port , tcphdr->seq , tcphdr->ack_seq , tcphdr->syn , tcphdr->ack , tcphdr->fin , tcphdr->psh , tcphdr->rst , tcphdr->urg
		, packet_data_len );
	DumpBuffer( "#stdout" , packet_data_len , packet_data );
#endif
	
	nret = ProcessTcpPacket( p_env , pcaphdr , etherhdr , iphdr , tcphdr , & tcpl_addr_hr , packet_data_len , packet_data ) ;
	if( nret )
	{
		printf( "*** ERROR : ProcessTcpPacket failed[%d]\n" , nret );
		exit(-nret);
	}
	
	return;
}

