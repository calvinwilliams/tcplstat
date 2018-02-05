/*
 * tcplstat - TCP packets monitor and statistical tool
 * author	: calvin
 * email	: calvinwilliams@163.com
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#include "tcplstat_in.h"

char	*_g_tcplstat_tcplsession_state[] = { "DISCONNECTED" , "CONNECTING" , "CONNECTED" , "DISCONNECTING" } ;

int ProcessTcpPacket( struct TcplStatEnv *p_env , const struct pcap_pkthdr *pcaphdr , struct ether_header *etherhdr , struct ip *iphdr , struct tcphdr *tcphdr , struct TcplAddrHumanReadable *p_tcpl_addr_hr , char *packet_data_intercepted , uint32_t packet_data_len_intercepted , uint32_t packet_data_len_actually )
{
	struct TcplSession	tcpl_session ;
	struct TcplSession	*p_tcpl_session = NULL ;
	struct TcplPacket	*p_last_tcpl_packet = NULL ;
	
	int			nret = 0 ;
	
	if( tcphdr->syn == 1 )
	{
		SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->ip_src , tcphdr->source , iphdr->ip_dst , tcphdr->dest )
		p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
		if( p_tcpl_session )
		{
			if( p_tcpl_session->status[0] == TCPLSESSION_STATUS_SYN )
			{
				printf( "*** WARN : [%s:%d]->[%s:%d] SYN DUPLICATED\n" , p_tcpl_addr_hr->src_ip , p_tcpl_addr_hr->src_port , p_tcpl_addr_hr->dst_ip , p_tcpl_addr_hr->dst_port );
				return 0;
			}
			else
			{
				printf( "*** ERROR : [%s:%d]->[%s:%d] status invalid\n" , p_tcpl_addr_hr->src_ip , p_tcpl_addr_hr->src_port , p_tcpl_addr_hr->dst_ip , p_tcpl_addr_hr->dst_port );
				UnlinkTcplSessionTreeNode( p_env , p_tcpl_session );
				free( p_tcpl_session );
				return -1;
			}
		}
		else
		{
			SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->ip_dst , tcphdr->dest , iphdr->ip_src , tcphdr->source )
			p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
			if( p_tcpl_session )
			{
				if( p_tcpl_session->status[1] == TCPLSESSION_STATUS_SYN )
				{
					printf( "*** WARN : [%s:%d]->[%s:%d] REVERSE SYN DUPLICATED\n" , p_tcpl_addr_hr->src_ip , p_tcpl_addr_hr->src_port , p_tcpl_addr_hr->dst_ip , p_tcpl_addr_hr->dst_port );
					return 0;
				}
				
				p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_list.this_node) , struct TcplPacket , this_node ) ;
				COPY_TIMEVAL( p_tcpl_session->wait_for_second_syn_and_first_ack_elapse , p_env->fixed_timestamp );
				DIFF_TIMEVAL( p_tcpl_session->wait_for_second_syn_and_first_ack_elapse , p_last_tcpl_packet->timestamp )
				
				p_tcpl_session->status[1] = TCPLSESSION_STATUS_SYN ;
				
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_OPPO_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
				if( nret )
					return nret;
				
				if( p_env->cmd_line_para.output_debug )
					OUTPUT_SESSION_EVENT( "MODIFY" , TCPLPACKET_OPPO_DIRECTION , p_tcpl_session )
				
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
				COPY_TIMEVAL( p_tcpl_session->begin_timestamp , p_env->fixed_timestamp )
				p_tcpl_session->state = TCPLSESSION_STATE_CONNECTING ;
				p_tcpl_session->status[0] = TCPLSESSION_STATUS_SYN ;
				INIT_LIST_HEAD( & (p_tcpl_session->tcpl_packets_list.this_node) );
				
				if( p_env->cmd_line_para.output_debug )
					OUTPUT_SESSION_EVENT( "ADD" , TCPLPACKET_DIRECTION , p_tcpl_session )
				
				nret = LinkTcplSessionTreeNode( p_env , p_tcpl_session ) ;
				if( nret )
					return nret;
				
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
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
		if( p_tcpl_session )
		{
			if( p_tcpl_session->status[0] == TCPLSESSION_STATUS_FIN )
			{
				return 0;
			}
			
			p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_list.this_node) , struct TcplPacket , this_node ) ;
			if( p_tcpl_session->status[1] == TCPLSESSION_STATUS_SYN )
			{
				COPY_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_env->fixed_timestamp );
				DIFF_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_last_tcpl_packet->timestamp )
			}
			else
			{
				COPY_TIMEVAL( p_tcpl_session->wait_for_second_fin_and_first_ack_elapse , p_env->fixed_timestamp );
				DIFF_TIMEVAL( p_tcpl_session->wait_for_second_fin_and_first_ack_elapse , p_last_tcpl_packet->timestamp )
			}
			
			p_tcpl_session->status[0] = TCPLSESSION_STATUS_FIN ;
			if( p_tcpl_session->state == TCPLSESSION_STATE_CONNECTED )
			{
				p_tcpl_session->state = TCPLSESSION_STATE_DISCONNECTING ;
				if( p_tcpl_session->disconnect_direction == TCPLSESSION_DISCONNECT_WAITFOR )
					p_tcpl_session->disconnect_direction = TCPLSESSION_DISCONNECT_DIRECTION ;
			}
			
			nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
			if( nret )
				return nret;
			
			if( p_env->cmd_line_para.output_debug )
				OUTPUT_SESSION_EVENT( "MODIFY" , TCPLPACKET_DIRECTION , p_tcpl_session )
			
			return 0;
		}
		else
		{
			SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->ip_dst , tcphdr->dest , iphdr->ip_src , tcphdr->source )
			p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
			if( p_tcpl_session )
			{
				if( p_tcpl_session->status[1] == TCPLSESSION_STATUS_FIN )
				{
					return 0;
				}
				
				p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_list.this_node) , struct TcplPacket , this_node ) ;
				if( p_tcpl_session->status[0] == TCPLSESSION_STATUS_SYN )
				{
					COPY_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_env->fixed_timestamp );
					DIFF_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_last_tcpl_packet->timestamp )
				}
				else
				{
					COPY_TIMEVAL( p_tcpl_session->wait_for_second_fin_and_first_ack_elapse , p_env->fixed_timestamp );
					DIFF_TIMEVAL( p_tcpl_session->wait_for_second_fin_and_first_ack_elapse , p_last_tcpl_packet->timestamp )
				}
				
				p_tcpl_session->status[1] = TCPLSESSION_STATUS_FIN ;
				if( p_tcpl_session->state == TCPLSESSION_STATE_CONNECTED )
				{
					p_tcpl_session->state = TCPLSESSION_STATE_DISCONNECTING ;
					if( p_tcpl_session->disconnect_direction == TCPLSESSION_DISCONNECT_WAITFOR )
						p_tcpl_session->disconnect_direction = TCPLSESSION_DISCONNECT_OPPO_DIRECTION ;
				}
				
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_OPPO_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
				if( nret )
					return nret;
				
				if( p_env->cmd_line_para.output_debug )
					OUTPUT_SESSION_EVENT( "MODIFY" , TCPLPACKET_OPPO_DIRECTION , p_tcpl_session )
				
				return 0;
			}
		}
	}
	
	if( tcphdr->rst == 1 )
	{
		SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->ip_src , tcphdr->source , iphdr->ip_dst , tcphdr->dest )
		p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
		if( p_tcpl_session )
		{
			p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_list.this_node) , struct TcplPacket , this_node ) ;
			COPY_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_env->fixed_timestamp );
			DIFF_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_last_tcpl_packet->timestamp )
			
			p_tcpl_session->state = TCPLSESSION_STATE_DISCONNECTED ;
			
			nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
			if( nret )
				return nret;
			
			if( p_env->cmd_line_para.output_debug )
				OUTPUT_SESSION_EVENT( "REMOVE" , TCPLPACKET_DIRECTION , p_tcpl_session )
			
			DumpTcplSession( p_env , pcaphdr , p_tcpl_session );
			UnlinkTcplSessionTreeNode( p_env , p_tcpl_session );
			free( p_tcpl_session );
			
			return 0;
		}
		else
		{
			SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->ip_dst , tcphdr->dest , iphdr->ip_src , tcphdr->source )
			p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
			if( p_tcpl_session )
			{
				p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_list.this_node) , struct TcplPacket , this_node ) ;
				COPY_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_env->fixed_timestamp );
				DIFF_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_last_tcpl_packet->timestamp )
				
				p_tcpl_session->state = TCPLSESSION_STATE_DISCONNECTED ;
				
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_OPPO_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
				if( nret )
					return nret;
				
				if( p_env->cmd_line_para.output_debug )
					OUTPUT_SESSION_EVENT( "REMOVE" , TCPLPACKET_OPPO_DIRECTION , p_tcpl_session )
				
				DumpTcplSession( p_env , pcaphdr , p_tcpl_session );
				UnlinkTcplSessionTreeNode( p_env , p_tcpl_session );
				free( p_tcpl_session );
				
				return 0;
			}
		}
	}
	
	SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->ip_src , tcphdr->source , iphdr->ip_dst , tcphdr->dest )
	p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
	if( p_tcpl_session )
	{
		if( p_tcpl_session->status[0] == TCPLSESSION_STATUS_SYN && p_tcpl_session->status[1] == TCPLSESSION_STATUS_SYN )
		{
			if( tcphdr->ack && p_tcpl_session->state == TCPLSESSION_STATE_CONNECTING )
			{
				p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_list.this_node) , struct TcplPacket , this_node ) ;
				COPY_TIMEVAL( p_tcpl_session->wait_for_after_syn_and_second_ack_elapse , p_env->fixed_timestamp );
				DIFF_TIMEVAL( p_tcpl_session->wait_for_after_syn_and_second_ack_elapse , p_last_tcpl_packet->timestamp )
			}
			
			nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
			if( nret )
				return nret;
			
			if( tcphdr->ack && p_tcpl_session->state == TCPLSESSION_STATE_CONNECTING )
			{
				p_tcpl_session->state = TCPLSESSION_STATE_CONNECTED ;
			}
			
			if( p_env->cmd_line_para.output_debug )
				OUTPUT_SESSION_EVENT( "MODIFY" , TCPLPACKET_DIRECTION , p_tcpl_session )
			
			return 0;
		}
		else if( p_tcpl_session->status[0] == TCPLSESSION_STATUS_FIN && p_tcpl_session->status[1] == TCPLSESSION_STATUS_FIN )
		{
			if( tcphdr->ack && p_tcpl_session->state == TCPLSESSION_STATE_DISCONNECTING && p_tcpl_session->disconnect_direction == TCPLSESSION_DISCONNECT_DIRECTION )
			{
				p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_list.this_node) , struct TcplPacket , this_node ) ;
				COPY_TIMEVAL( p_tcpl_session->wait_for_second_ack_elapse , p_env->fixed_timestamp );
				DIFF_TIMEVAL( p_tcpl_session->wait_for_second_ack_elapse , p_last_tcpl_packet->timestamp )
				
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
				if( nret )
					return nret;
				
				p_tcpl_session->state = TCPLSESSION_STATE_DISCONNECTED ;
				
				if( p_env->cmd_line_para.output_debug )
					OUTPUT_SESSION_EVENT( "REMOVE" , TCPLPACKET_DIRECTION , p_tcpl_session )
				
				DumpTcplSession( p_env , pcaphdr , p_tcpl_session );
				UnlinkTcplSessionTreeNode( p_env , p_tcpl_session );
				free( p_tcpl_session );
				
				return 0;
			}
		}
	}
	else
	{
		SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->ip_dst , tcphdr->dest , iphdr->ip_src , tcphdr->source )
		p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
		if( p_tcpl_session )
		{
			if( p_tcpl_session->status[1] == TCPLSESSION_STATUS_SYN && p_tcpl_session->status[0] == TCPLSESSION_STATUS_SYN )
			{
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_OPPO_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
				if( nret )
					return nret;
				
				if( p_env->cmd_line_para.output_debug )
					OUTPUT_SESSION_EVENT( "MODIFY" , TCPLPACKET_OPPO_DIRECTION , p_tcpl_session )
				
				return 0;
			}
			else if( p_tcpl_session->status[1] == TCPLSESSION_STATUS_FIN && p_tcpl_session->status[0] == TCPLSESSION_STATUS_FIN )
			{
				if( tcphdr->ack && p_tcpl_session->state == TCPLSESSION_STATE_DISCONNECTING && p_tcpl_session->disconnect_direction == TCPLSESSION_DISCONNECT_OPPO_DIRECTION )
				{
					p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_list.this_node) , struct TcplPacket , this_node ) ;
					COPY_TIMEVAL( p_tcpl_session->wait_for_second_ack_elapse , p_env->fixed_timestamp );
					DIFF_TIMEVAL( p_tcpl_session->wait_for_second_ack_elapse , p_last_tcpl_packet->timestamp )
					
					nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_OPPO_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
					if( nret )
						return nret;
					
					p_tcpl_session->state = TCPLSESSION_STATE_DISCONNECTED ;
					
					if( p_env->cmd_line_para.output_debug )
						OUTPUT_SESSION_EVENT( "REMOVE" , TCPLPACKET_OPPO_DIRECTION , p_tcpl_session )
					
					DumpTcplSession( p_env , pcaphdr , p_tcpl_session );
					UnlinkTcplSessionTreeNode( p_env , p_tcpl_session );
					free( p_tcpl_session );
					
					return 0;
				}
			}
		}
	}
	
	printf( "*** ERROR : [%s:%d]->[%s:%d] unknow tcp packet\n" , p_tcpl_addr_hr->src_ip , p_tcpl_addr_hr->src_port , p_tcpl_addr_hr->dst_ip , p_tcpl_addr_hr->dst_port );
	
	return 0;
}

