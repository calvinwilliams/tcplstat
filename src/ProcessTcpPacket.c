#include "tcplstat_in.h"

static char _g_tcpl_packet_flag[] = { 'U' , 'S' , 'F' , 'D' , 'A' } ;

static int AddTcpPacket( struct TcplStatEnv *p_env , const struct pcap_pkthdr *pcaphdr , struct TcplSession *p_tcpl_session , int direct_flag , int packet_flag , uint32_t packet_data_len , char *packet_data )
{
	struct TcplPacket	*p_tcpl_packet = NULL ;
	struct TcplPacket	*p_oppo_direct_tcpl_packet = NULL ;
	
	p_tcpl_packet = (struct TcplPacket *)malloc( sizeof(struct TcplPacket) ) ;
	if( p_tcpl_packet == NULL )
	{
		printf( "*** ERROR : alloc failed , errno[%d]\n" , errno );
		exit(1);
	}
	memset( p_tcpl_packet , 0x00 , sizeof(struct TcplPacket) );
	
	COPY_TIMEVAL( p_tcpl_packet->timestamp , pcaphdr->ts )
	
	p_tcpl_packet->direct_flag = direct_flag ;
	
	if( direct_flag == 0 )
		p_oppo_direct_tcpl_packet = p_tcpl_session->p_recent_sent_packet ;
	else
		p_oppo_direct_tcpl_packet = p_tcpl_session->p_recent_recv_packet ;
	if( p_oppo_direct_tcpl_packet )
	{
		gettimeofday( & (p_tcpl_packet->diff_opposite_direction) , NULL );
		DIFF_TIMEVAL( p_tcpl_packet->diff_opposite_direction , p_oppo_direct_tcpl_packet->timestamp )
	}
	
	p_tcpl_packet->packet_flag = packet_flag ;
	p_tcpl_packet->packet_data_len = packet_data_len ;
	if( packet_data_len == 0 )
		p_tcpl_packet->packet_data = "" ;
	else
		p_tcpl_packet->packet_data = memndup( packet_data , packet_data_len ) ;
	if( p_tcpl_packet == NULL )
	{
		printf( "*** ERROR : alloc tcpl_packet failed , errno[%d]\n" , errno );
		free( p_tcpl_packet );
		return -1;
	}
	
#if _DEBUG
	printf( "DEBUG - timestamp[%ld.%06ld] diff_timestamp[%ld.%06ld] packet_flag[%c] packet_data_len[%u]\n"
		, p_tcpl_packet->timestamp.tv_sec , p_tcpl_packet->timestamp.tv_usec , p_tcpl_packet->diff_opposite_direction.tv_sec , p_tcpl_packet->diff_opposite_direction.tv_usec
		, _g_tcpl_packet_flag[p_tcpl_packet->packet_flag] , p_tcpl_packet->packet_data_len );
	if( p_env->cmd_line_para.output_level >= OUTPUT_LEVEL_3 )
	{
		DumpBuffer( "#stdout" , p_tcpl_packet->packet_data_len , p_tcpl_packet->packet_data );
	}
#endif
	list_add_tail( & (p_tcpl_packet->this_node) , & (p_tcpl_session->tcpl_packets_list.this_node) );
	
	if( direct_flag == 0 && p_tcpl_session->p_recent_recv_packet == NULL )
		p_tcpl_session->p_recent_recv_packet = p_tcpl_packet ;
	else if( direct_flag == 1 && p_tcpl_session->p_recent_sent_packet )
		p_tcpl_session->p_recent_sent_packet = p_tcpl_packet ;
	
	return 0;
}

static void DumpTcplSession( struct TcplStatEnv *p_env , struct TcplSession *p_tcpl_session , struct TcplAddrHumanReadable *p_tcpl_addr_hr )
{
	struct TcplPacket	*p_tcpl_packet = NULL ;
	struct TcplPacket	*p_next_tcpl_packet = NULL ;
	
	if( p_env->cmd_line_para.output_level >= OUTPUT_LEVEL_1 )
	{
		printf( "[%s:%d]->[%s:%d] %ld.%06ld\n"
			, p_tcpl_addr_hr->src_ip , p_tcpl_addr_hr->src_port , p_tcpl_addr_hr->dst_ip , p_tcpl_addr_hr->dst_port
			, p_tcpl_session->begin_timestamp.tv_sec , p_tcpl_session->begin_timestamp.tv_usec );
	}
	
	if( p_env->cmd_line_para.output_level >= OUTPUT_LEVEL_2 )
	{
		list_for_each_entry_safe( p_tcpl_packet , p_next_tcpl_packet , & (p_tcpl_session->tcpl_packets_list.this_node) , struct TcplPacket , this_node )
		{
			char	*direct_string = NULL ;
			
			if( p_tcpl_packet->direct_flag == 0 )
				direct_string = "->" ;
			else
				direct_string = "<-" ;
			
			printf( "\t%ld.%06ld %ld.%06ld [%s:%d]%s[%s:%d] %c %u\n"
				, p_tcpl_packet->timestamp.tv_sec , p_tcpl_packet->timestamp.tv_usec
				, p_tcpl_packet->diff_opposite_direction.tv_sec , p_tcpl_packet->diff_opposite_direction.tv_usec
				, p_tcpl_session->tcpl_addr_hr.src_ip , p_tcpl_session->tcpl_addr_hr.src_port
				, direct_string
				, p_tcpl_session->tcpl_addr_hr.dst_ip , p_tcpl_session->tcpl_addr_hr.dst_port
				, _g_tcpl_packet_flag[p_tcpl_packet->packet_flag] , p_tcpl_packet->packet_data_len );
			if( p_env->cmd_line_para.output_level >= OUTPUT_LEVEL_3 )
			{
				if( p_tcpl_packet->packet_data_len > 0 )
				{
					DumpBuffer( "#stdout" , p_tcpl_packet->packet_data_len , p_tcpl_packet->packet_data );
				}
			}
			
			list_del( & (p_tcpl_packet->this_node) );
			free( p_tcpl_packet );
		}
	}
	
	return;
}

int ProcessTcpPacket( struct TcplStatEnv *p_env , const struct pcap_pkthdr *pcaphdr , struct ether_header *etherhdr , struct ip *iphdr , struct tcphdr *tcphdr , struct TcplAddrHumanReadable *p_tcpl_addr_hr , uint32_t packet_data_len , char *packet_data )
{
	struct TcplSession	tcpl_session ;
	struct TcplSession	*p_tcpl_session = NULL ;
	
	int			nret = 0 ;
	
	if( tcphdr->syn == 1 )
	{
		SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->ip_src , tcphdr->source , iphdr->ip_dst , tcphdr->dest )
		p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
#if _DEBUG
		printf( "DEBUG - syn - QueryTcplSessionTreeNode return[%p]\n" , p_tcpl_session );
		DumpBuffer( "#stdout" , sizeof(struct TcplSessionId) , & (tcpl_session.session_id) );
#endif
		if( p_tcpl_session )
		{
			if( p_tcpl_session->status[0] == TCPLSESSION_STATUS_SYN )
			{
				printf( "*** ERROR : [%s:%d]->[%s:%d] syn duplicated 2\n" , p_tcpl_addr_hr->src_ip , p_tcpl_addr_hr->src_port , p_tcpl_addr_hr->dst_ip , p_tcpl_addr_hr->dst_port );
				UnlinkTcplSessionTreeNode( p_env , p_tcpl_session );
				free( p_tcpl_session );
				return -1;
			}
			else
			{
				printf( "*** ERROR : [%s:%d]->[%s:%d] syn duplicated\n" , p_tcpl_addr_hr->src_ip , p_tcpl_addr_hr->src_port , p_tcpl_addr_hr->dst_ip , p_tcpl_addr_hr->dst_port );
				UnlinkTcplSessionTreeNode( p_env , p_tcpl_session );
				free( p_tcpl_session );
				return -1;
			}
		}
		else
		{
			SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->ip_dst , tcphdr->dest , iphdr->ip_src , tcphdr->source )
			p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
#if _DEBUG
			printf( "DEBUG - reverse syn - QueryTcplSessionTreeNode return[%p]\n" , p_tcpl_session );
			DumpBuffer( "#stdout" , sizeof(struct TcplSessionId) , & (tcpl_session.session_id) );
#endif
			if( p_tcpl_session )
			{
				if( p_tcpl_session->status[1] == TCPLSESSION_STATUS_SYN )
				{
					printf( "*** ERROR : [%s:%d]->[%s:%d] reverse syn duplicated 2\n" , p_tcpl_addr_hr->src_ip , p_tcpl_addr_hr->src_port , p_tcpl_addr_hr->dst_ip , p_tcpl_addr_hr->dst_port );
					UnlinkTcplSessionTreeNode( p_env , p_tcpl_session );
					free( p_tcpl_session );
					return -1;
				}
				
				p_tcpl_session->status[1] = TCPLSESSION_STATUS_SYN ;
				
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , 1 , TCPLPACKET_FLAG_SYN , packet_data_len , packet_data ) ;
				if( nret )
					return nret;
				
				return 0;
			}
			else
			{
				p_tcpl_session = (struct TcplSession *)malloc( sizeof(struct TcplSession) ) ;
				if( p_tcpl_session == NULL )
				{
					printf( "*** ERROR : alloc failed , errno[%d]\n" , errno );
					exit(1);
				}
				memset( p_tcpl_session , 0x00 , sizeof(struct TcplSession) );
				
				SET_TCPL_SESSION_ID( p_tcpl_session->tcpl_session_id , iphdr->ip_src , tcphdr->source , iphdr->ip_dst , tcphdr->dest )
				memcpy( & (p_tcpl_session->tcpl_addr_hr) , p_tcpl_addr_hr , sizeof(struct TcplAddrHumanReadable) );
				COPY_TIMEVAL( p_tcpl_session->begin_timestamp , pcaphdr->ts )
				p_tcpl_session->status[0] = TCPLSESSION_STATUS_SYN ;
				INIT_LIST_HEAD( & (p_tcpl_session->tcpl_packets_list.this_node) );
				
				nret = LinkTcplSessionTreeNode( p_env , p_tcpl_session ) ;
#if _DEBUG
				printf( "DEBUG - LinkTcplSessionTreeNode return [%d]\n" , nret );
				DumpBuffer( "#stdout" , sizeof(struct TcplSessionId) , & (p_tcpl_session->session_id) );
#endif
				if( nret )
					return nret;
				
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , 0 , TCPLPACKET_FLAG_SYN , packet_data_len , packet_data ) ;
				if( nret )
					return nret;
				
				return 0;
			}
		}
	}
	
	if( tcphdr->fin == 1 )
	{
		SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->ip_src , tcphdr->source , iphdr->ip_dst , tcphdr->dest )
		p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
#if _DEBUG
		printf( "DEBUG - fin - QueryTcplSessionTreeNode return[%p]\n" , p_tcpl_session );
		DumpBuffer( "#stdout" , sizeof(struct TcplSessionId) , & (tcpl_session.session_id) );
#endif
		if( p_tcpl_session )
		{
			if( p_tcpl_session->status[0] == TCPLSESSION_STATUS_SYN )
			{
				p_tcpl_session->status[0] = TCPLSESSION_STATUS_FIN ;
				
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , 0 , TCPLPACKET_FLAG_FIN , packet_data_len , packet_data ) ;
				if( nret )
					return nret;
			}
			
			if( p_tcpl_session->status[0] == TCPLSESSION_STATUS_FIN && p_tcpl_session->status[1] == TCPLSESSION_STATUS_FIN )
			{
				DumpTcplSession( p_env , p_tcpl_session , p_tcpl_addr_hr );
#if _DEBUG
				printf( "DEBUG - UnlinkTcplSessionTreeNode\n" );
				DumpBuffer( "#stdout" , sizeof(struct TcplSessionId) , & (p_tcpl_session->session_id) );
#endif
				UnlinkTcplSessionTreeNode( p_env , p_tcpl_session );
				free( p_tcpl_session );
			}
			
			return 0;
		}
		else
		{
			SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->ip_dst , tcphdr->dest , iphdr->ip_src , tcphdr->source )
			p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
#if _DEBUG
			printf( "DEBUG - reverse fin - QueryTcplSessionTreeNode return[%p]\n" , p_tcpl_session );
			DumpBuffer( "#stdout" , sizeof(struct TcplSessionId) , & (tcpl_session.session_id) );
#endif
			if( p_tcpl_session )
			{
				if( p_tcpl_session->status[1] == TCPLSESSION_STATUS_SYN )
				{
					p_tcpl_session->status[1] = TCPLSESSION_STATUS_FIN ;
					
					nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , 1 , TCPLPACKET_FLAG_FIN , packet_data_len , packet_data ) ;
					if( nret )
						return nret;
				}
				
				if( p_tcpl_session->status[1] == TCPLSESSION_STATUS_FIN && p_tcpl_session->status[0] == TCPLSESSION_STATUS_FIN )
				{
					DumpTcplSession( p_env , p_tcpl_session , p_tcpl_addr_hr );
#if _DEBUG
					printf( "DEBUG - UnlinkTcplSessionTreeNode2\n" );
					DumpBuffer( "#stdout" , sizeof(struct TcplSessionId) , & (p_tcpl_session->session_id) );
#endif
					UnlinkTcplSessionTreeNode( p_env , p_tcpl_session );
					free( p_tcpl_session );
				}
				
				return 0;
			}
			else
			{
				return 0;
			}
		}
	}
	
	SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->ip_src , tcphdr->source , iphdr->ip_dst , tcphdr->dest )
	p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
#if _DEBUG
		printf( "DEBUG - %s - QueryTcplSessionTreeNode return[%p]\n" , tcphdr->ack?"ack":"dat" , p_tcpl_session );
		DumpBuffer( "#stdout" , sizeof(struct TcplSessionId) , & (tcpl_session.session_id) );
#endif
	if( p_tcpl_session )
	{
		if( p_tcpl_session->status[0] == TCPLSESSION_STATUS_SYN && p_tcpl_session->status[1] == TCPLSESSION_STATUS_SYN )
		{
			nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , 0 , tcphdr->ack?TCPLPACKET_FLAG_ACK:TCPLPACKET_FLAG_DAT , packet_data_len , packet_data ) ;
			if( nret )
				return nret;
			
			return 0;
		}
	}
	else
	{
		SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->ip_dst , tcphdr->dest , iphdr->ip_src , tcphdr->source )
		p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
#if _DEBUG
		printf( "DEBUG - reverse %s - QueryTcplSessionTreeNode return[%p]\n" , tcphdr->ack?"ack":"dat" , p_tcpl_session );
		DumpBuffer( "#stdout" , sizeof(struct TcplSessionId) , & (tcpl_session.session_id) );
#endif
		if( p_tcpl_session )
		{
			if( p_tcpl_session->status[1] == TCPLSESSION_STATUS_SYN && p_tcpl_session->status[0] == TCPLSESSION_STATUS_SYN )
			{
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , 0 , tcphdr->ack?TCPLPACKET_FLAG_ACK:TCPLPACKET_FLAG_DAT , packet_data_len , packet_data ) ;
				if( nret )
					return nret;
				
				return 0;
			}
		}
	}
	
	printf( "[%s:%d]->[%s:%d] unknow tcp packet\n" , p_tcpl_addr_hr->src_ip , p_tcpl_addr_hr->src_port , p_tcpl_addr_hr->dst_ip , p_tcpl_addr_hr->dst_port );
	
	return 0;
}

