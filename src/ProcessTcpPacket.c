/*
 * tcplstat - TCP packets monitor and statistical tool
 * author	: calvin
 * email	: calvinwilliams@163.com
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#include "tcplstat_in.h"

char	*_g_tcplstat_tcplsession_state[] = { "DISCONNECTED" , "CONNECTING" , "CONNECTED" , "DISCONNECTING" } ;

/* 处理TCP分组 */
int ProcessTcpPacket( struct TcplStatEnv *p_env , const struct pcap_pkthdr *pcaphdr , struct NetinetEthernetHeader *etherhdr , struct NetinetIpHeader *iphdr , struct NetinetTcpHeader *tcphdr , struct TcplAddrHumanReadable *p_tcpl_addr_hr , char *packet_data_intercepted , uint32_t packet_data_len_intercepted , uint32_t packet_data_len_actually )
{
	struct TcplSession	tcpl_session ;
	struct TcplSession	*p_tcpl_session = NULL ;
	struct TcplPacket	*p_last_tcpl_packet = NULL ;
	
	int			nret = 0 ;
	
	/* 如果TCP分组带有SYN标志 */
	if( TH_FLAG(tcphdr,TH_SYN) )
	{
		/* 查询正向会话ID */
		SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->_ip_src , tcphdr->_th_sport , iphdr->_ip_dst , tcphdr->_th_dport )
		p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
		if( p_tcpl_session )
		{
			/* 重复收到SYN包 */
			if( p_tcpl_session->status[0] == TCPLSESSION_STATUS_SYN )
			{
				fprintf( p_env->fp , "*** WARN : [%s:%d]->[%s:%d] SYN DUPLICATED\n" , p_tcpl_addr_hr->src_ip , p_tcpl_addr_hr->src_port , p_tcpl_addr_hr->dst_ip , p_tcpl_addr_hr->dst_port );
				return 0;
			}
			/* 未曾收到SYN包而莫名其妙建立的会话，后又收到SYN包 */
			else
			{
				fprintf( p_env->fp , "*** ERROR : [%s:%d]->[%s:%d] status invalid\n" , p_tcpl_addr_hr->src_ip , p_tcpl_addr_hr->src_port , p_tcpl_addr_hr->dst_ip , p_tcpl_addr_hr->dst_port );
				UnlinkTcplSessionTreeNode( p_env , p_tcpl_session );
				if( p_env->unused_tcpl_session_count < PENV_MAX_UNUSED_TCPLSESSION_COUNT )
				{
					RECYCLING_TCPL_SESSION( p_env , p_tcpl_session );
				}
				else
				{
					DELETE_TCPL_SESSION( p_env , p_tcpl_session );
				}
				return 0;
			}
		}
		else
		{
			/* 查询反向会话ID */
			SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->_ip_dst , tcphdr->_th_dport , iphdr->_ip_src , tcphdr->_th_sport )
			p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
			if( p_tcpl_session )
			{
				/* 重复收到SYN包 */
				if( p_tcpl_session->status[1] == TCPLSESSION_STATUS_SYN )
				{
					fprintf( p_env->fp , "*** WARN : [%s:%d]->[%s:%d] REVERSE SYN DUPLICATED\n" , p_tcpl_addr_hr->src_ip , p_tcpl_addr_hr->src_port , p_tcpl_addr_hr->dst_ip , p_tcpl_addr_hr->dst_port );
					return 0;
				}
				
				/* 统计发出SYN后收到SYN+ACK的延迟 */
				p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_trace_list.this_node) , struct TcplPacket , this_node ) ;
				COPY_TIMEVAL( p_tcpl_session->wait_for_second_syn_and_first_ack_elapse , p_env->fixed_timestamp );
				DIFF_TIMEVAL( p_tcpl_session->wait_for_second_syn_and_first_ack_elapse , p_last_tcpl_packet->timestamp )
				
				p_tcpl_session->status[1] = TCPLSESSION_STATUS_SYN ;
				
				/* 记录TCP分组明细 */
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_OPPO_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
				if( nret )
					return nret;
				
				if( p_env->cmd_line_para.output_debug )
					OUTPUT_SESSION_EVENT( "MODIFY" , TCPLPACKET_OPPO_DIRECTION , p_tcpl_session )
				
				return 0;
			}
			else
			{
				/* 未查询到会话，收到第一个SYN包，正常建立会话 */
				if( p_env->unused_tcpl_session_count == 0 )
				{
					p_tcpl_session = (struct TcplSession *)malloc( sizeof(struct TcplSession) ) ;
					if( p_tcpl_session == NULL )
					{
						fprintf( p_env->fp , "*** ERROR : alloc failed , errno[%d]\n" , errno );
						exit(1);
					}
					memset( p_tcpl_session , 0x00 , sizeof(struct TcplSession) );
				}
				else
				{
					REUSE_TCPL_SESSION( p_env , p_tcpl_session )
				}
				
				SET_TCPL_SESSION_ID( p_tcpl_session->tcpl_session_id , iphdr->_ip_src , tcphdr->_th_sport , iphdr->_ip_dst , tcphdr->_th_dport )
				memcpy( & (p_tcpl_session->tcpl_addr_hr) , p_tcpl_addr_hr , sizeof(struct TcplAddrHumanReadable) );
				COPY_TIMEVAL( p_tcpl_session->begin_timestamp , p_env->fixed_timestamp )
				p_tcpl_session->state = TCPLSESSION_STATE_CONNECTING ;
				p_tcpl_session->status[0] = TCPLSESSION_STATUS_SYN ;
				INIT_LIST_HEAD( & (p_tcpl_session->tcpl_packets_trace_list.this_node) );
				
				if( p_env->cmd_line_para.output_debug )
					OUTPUT_SESSION_EVENT( "ADD" , TCPLPACKET_DIRECTION , p_tcpl_session )
				
				/* 新建会话，挂到会话树上 */
				nret = LinkTcplSessionTreeNode( p_env , p_tcpl_session ) ;
				if( nret )
					return nret;
				
				/* 记录TCP分组明细 */
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
				if( nret )
					return nret;
				
				return 0;
			}
		}
	}
	
	/* 如果TCP分组带有FIN标志 */
	if( TH_FLAG(tcphdr,TH_FIN) )
	{
		/* 查询正向会话ID */
		SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->_ip_src , tcphdr->_th_sport , iphdr->_ip_dst , tcphdr->_th_dport )
		p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
		if( p_tcpl_session )
		{
			/* 重复收到FIN包 */
			if( p_tcpl_session->status[0] == TCPLSESSION_STATUS_FIN )
			{
				return 0;
			}
			
			p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_trace_list.this_node) , struct TcplPacket , this_node ) ;
			if( p_tcpl_session->status[1] == TCPLSESSION_STATUS_SYN )
			{
				/* 反向先发送FIN包 */
				COPY_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_env->fixed_timestamp );
				DIFF_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_last_tcpl_packet->timestamp )
			}
			else
			{
				/* 正向先发送FIN包 */
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
			
			/* 记录TCP分组明细 */
			nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
			if( nret )
				return nret;
			
			if( p_env->cmd_line_para.output_debug )
				OUTPUT_SESSION_EVENT( "MODIFY" , TCPLPACKET_DIRECTION , p_tcpl_session )
			
			return 0;
		}
		else
		{
			/* 查询反向会话ID */
			SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->_ip_dst , tcphdr->_th_dport , iphdr->_ip_src , tcphdr->_th_sport )
			p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
			if( p_tcpl_session )
			{
				if( p_tcpl_session->status[1] == TCPLSESSION_STATUS_FIN )
				{
					return 0;
				}
				
				p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_trace_list.this_node) , struct TcplPacket , this_node ) ;
				if( p_tcpl_session->status[0] == TCPLSESSION_STATUS_SYN )
				{
					/* 正向先发送FIN包 */
					COPY_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_env->fixed_timestamp );
					DIFF_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_last_tcpl_packet->timestamp )
				}
				else
				{
					/* 反向先发送FIN包 */
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
				
				/* 记录TCP分组明细 */
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_OPPO_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
				if( nret )
					return nret;
				
				if( p_env->cmd_line_para.output_debug )
					OUTPUT_SESSION_EVENT( "MODIFY" , TCPLPACKET_OPPO_DIRECTION , p_tcpl_session )
				
				return 0;
			}
		}
	}
	
	/* 如果TCP分组带有RST标志 */
	if( TH_FLAG(tcphdr,TH_RST) )
	{
		/* 查询正向会话ID */
		SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->_ip_src , tcphdr->_th_sport , iphdr->_ip_dst , tcphdr->_th_dport )
		p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
		if( p_tcpl_session )
		{
			/* 统计第一个FIN包延迟 */
			p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_trace_list.this_node) , struct TcplPacket , this_node ) ;
			COPY_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_env->fixed_timestamp );
			DIFF_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_last_tcpl_packet->timestamp )
			
			p_tcpl_session->state = TCPLSESSION_STATE_DISCONNECTED ;
			
			/* 记录TCP分组明细 */
			nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
			if( nret )
				return nret;
			
			if( p_env->cmd_line_para.output_debug )
				OUTPUT_SESSION_EVENT( "REMOVE" , TCPLPACKET_DIRECTION , p_tcpl_session )
			
			/* 输出TCP会话信息 */
			OutputTcplSession( p_env , pcaphdr , p_tcpl_session );
			
			/* 从TCP会话树上删除 */
			UnlinkTcplSessionTreeNode( p_env , p_tcpl_session );
			if( p_env->unused_tcpl_session_count < PENV_MAX_UNUSED_TCPLSESSION_COUNT )
			{
				RECYCLING_TCPL_SESSION( p_env , p_tcpl_session );
			}
			else
			{
				DELETE_TCPL_SESSION( p_env , p_tcpl_session );
			}
			
			return 0;
		}
		else
		{
			/* 查询反向会话ID */
			SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->_ip_dst , tcphdr->_th_dport , iphdr->_ip_src , tcphdr->_th_sport )
			p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
			if( p_tcpl_session )
			{
				/* 统计第一个FIN包延迟 */
				p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_trace_list.this_node) , struct TcplPacket , this_node ) ;
				COPY_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_env->fixed_timestamp );
				DIFF_TIMEVAL( p_tcpl_session->wait_for_first_fin_elapse , p_last_tcpl_packet->timestamp )
				
				p_tcpl_session->state = TCPLSESSION_STATE_DISCONNECTED ;
				
				/* 记录TCP分组明细 */
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_OPPO_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
				if( nret )
					return nret;
				
				if( p_env->cmd_line_para.output_debug )
					OUTPUT_SESSION_EVENT( "REMOVE" , TCPLPACKET_OPPO_DIRECTION , p_tcpl_session )
				
				/* 输出TCP会话信息 */
				OutputTcplSession( p_env , pcaphdr , p_tcpl_session );
				
				/* 从TCP会话树上删除 */
				UnlinkTcplSessionTreeNode( p_env , p_tcpl_session );
				if( p_env->unused_tcpl_session_count < PENV_MAX_UNUSED_TCPLSESSION_COUNT )
				{
					RECYCLING_TCPL_SESSION( p_env , p_tcpl_session );
				}
				else
				{
					DELETE_TCPL_SESSION( p_env , p_tcpl_session );
				}
				
				return 0;
			}
		}
	}
	
	/* 如果TCP分组带有ACK标志或其它标志 */
	/* 查询正向会话ID */
	SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->_ip_src , tcphdr->_th_sport , iphdr->_ip_dst , tcphdr->_th_dport )
	p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
	if( p_tcpl_session )
	{
		if( p_tcpl_session->status[0] == TCPLSESSION_STATUS_SYN && p_tcpl_session->status[1] == TCPLSESSION_STATUS_SYN )
		{
			/* 收到三步握手的最后一个ACK 或者 正常TCP分组往来 */
			
			if( TH_FLAG(tcphdr,TH_ACK) && p_tcpl_session->state == TCPLSESSION_STATE_CONNECTING )
			{
				p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_trace_list.this_node) , struct TcplPacket , this_node ) ;
				COPY_TIMEVAL( p_tcpl_session->wait_for_after_syn_and_second_ack_elapse , p_env->fixed_timestamp );
				DIFF_TIMEVAL( p_tcpl_session->wait_for_after_syn_and_second_ack_elapse , p_last_tcpl_packet->timestamp )
			}
			
			/* 记录TCP分组明细 */
			nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
			if( nret )
				return nret;
			
			if( TH_FLAG(tcphdr,TH_ACK) && p_tcpl_session->state == TCPLSESSION_STATE_CONNECTING )
			{
				p_tcpl_session->state = TCPLSESSION_STATE_CONNECTED ;
			}
			
			if( p_env->cmd_line_para.output_debug )
				OUTPUT_SESSION_EVENT( "MODIFY" , TCPLPACKET_DIRECTION , p_tcpl_session )
			
			if( p_tcpl_session->total_packet_trace_count >= p_env->cmd_line_para.max_packet_trace_count )
			{
				/* 输出TCP会话信息 */
				OutputTcplSession( p_env , pcaphdr , p_tcpl_session );
			}
			
			return 0;
		}
		else if( p_tcpl_session->status[0] == TCPLSESSION_STATUS_FIN && p_tcpl_session->status[1] == TCPLSESSION_STATUS_FIN )
		{
			/* 收到四步分手的最后一个ACK */
			if( TH_FLAG(tcphdr,TH_ACK) && p_tcpl_session->state == TCPLSESSION_STATE_DISCONNECTING && p_tcpl_session->disconnect_direction == TCPLSESSION_DISCONNECT_DIRECTION )
			{
				p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_trace_list.this_node) , struct TcplPacket , this_node ) ;
				COPY_TIMEVAL( p_tcpl_session->wait_for_second_ack_elapse , p_env->fixed_timestamp );
				DIFF_TIMEVAL( p_tcpl_session->wait_for_second_ack_elapse , p_last_tcpl_packet->timestamp )
				
				/* 记录TCP分组明细 */
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
				if( nret )
					return nret;
				
				p_tcpl_session->state = TCPLSESSION_STATE_DISCONNECTED ;
				
				if( p_env->cmd_line_para.output_debug )
					OUTPUT_SESSION_EVENT( "REMOVE" , TCPLPACKET_DIRECTION , p_tcpl_session )
				
				/* 输出TCP会话信息 */
				OutputTcplSession( p_env , pcaphdr , p_tcpl_session );
				
				/* 从TCP会话树上删除 */
				UnlinkTcplSessionTreeNode( p_env , p_tcpl_session );
				if( p_env->unused_tcpl_session_count < PENV_MAX_UNUSED_TCPLSESSION_COUNT )
				{
					RECYCLING_TCPL_SESSION( p_env , p_tcpl_session );
				}
				else
				{
					DELETE_TCPL_SESSION( p_env , p_tcpl_session );
				}
				
				return 0;
			}
		}
	}
	else
	{
		/* 查询反向会话ID */
		SET_TCPL_SESSION_ID( tcpl_session.tcpl_session_id , iphdr->_ip_dst , tcphdr->_th_dport , iphdr->_ip_src , tcphdr->_th_sport )
		p_tcpl_session = QueryTcplSessionTreeNode( p_env , & tcpl_session ) ;
		if( p_tcpl_session )
		{
			/* 正常TCP分组往来 */
			if( p_tcpl_session->status[1] == TCPLSESSION_STATUS_SYN && p_tcpl_session->status[0] == TCPLSESSION_STATUS_SYN )
			{
				nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_OPPO_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
				if( nret )
					return nret;
				
				if( p_env->cmd_line_para.output_debug )
					OUTPUT_SESSION_EVENT( "MODIFY" , TCPLPACKET_OPPO_DIRECTION , p_tcpl_session )
				
				if( p_tcpl_session->total_packet_trace_count >= p_env->cmd_line_para.max_packet_trace_count )
				{
					/* 输出TCP会话信息 */
					OutputTcplSession( p_env , pcaphdr , p_tcpl_session );
				}
				
				return 0;
			}
			else if( p_tcpl_session->status[1] == TCPLSESSION_STATUS_FIN && p_tcpl_session->status[0] == TCPLSESSION_STATUS_FIN )
			{
				/* 收到四步分手的最后一个ACK */
				if( TH_FLAG(tcphdr,TH_ACK) && p_tcpl_session->state == TCPLSESSION_STATE_DISCONNECTING && p_tcpl_session->disconnect_direction == TCPLSESSION_DISCONNECT_OPPO_DIRECTION )
				{
					p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_trace_list.this_node) , struct TcplPacket , this_node ) ;
					COPY_TIMEVAL( p_tcpl_session->wait_for_second_ack_elapse , p_env->fixed_timestamp );
					DIFF_TIMEVAL( p_tcpl_session->wait_for_second_ack_elapse , p_last_tcpl_packet->timestamp )
					
					/* 记录TCP分组明细 */
					nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_OPPO_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
					if( nret )
						return nret;
					
					p_tcpl_session->state = TCPLSESSION_STATE_DISCONNECTED ;
					
					if( p_env->cmd_line_para.output_debug )
						OUTPUT_SESSION_EVENT( "REMOVE" , TCPLPACKET_OPPO_DIRECTION , p_tcpl_session )
					
					/* 输出TCP会话信息 */
					OutputTcplSession( p_env , pcaphdr , p_tcpl_session );
					
					/* 从TCP会话树上删除 */
					UnlinkTcplSessionTreeNode( p_env , p_tcpl_session );
					if( p_env->unused_tcpl_session_count < PENV_MAX_UNUSED_TCPLSESSION_COUNT )
					{
						RECYCLING_TCPL_SESSION( p_env , p_tcpl_session );
					}
					else
					{
						DELETE_TCPL_SESSION( p_env , p_tcpl_session );
					}
					
					return 0;
				}
			}
		}
		else
		{
			/* 连接中开始嗅探，就当补建立会话 */
			
			p_tcpl_session = (struct TcplSession *)malloc( sizeof(struct TcplSession) ) ;
			if( p_tcpl_session == NULL )
			{
				fprintf( p_env->fp , "*** ERROR : alloc failed , errno[%d]\n" , errno );
				exit(1);
			}
			memset( p_tcpl_session , 0x00 , sizeof(struct TcplSession) );
			
			SET_TCPL_SESSION_ID( p_tcpl_session->tcpl_session_id , iphdr->_ip_src , tcphdr->_th_sport , iphdr->_ip_dst , tcphdr->_th_dport )
			memcpy( & (p_tcpl_session->tcpl_addr_hr) , p_tcpl_addr_hr , sizeof(struct TcplAddrHumanReadable) );
			COPY_TIMEVAL( p_tcpl_session->begin_timestamp , p_env->fixed_timestamp )
			p_tcpl_session->state = TCPLSESSION_STATE_CONNECTED ;
			p_tcpl_session->status[0] = TCPLSESSION_STATUS_SYN ;
			p_tcpl_session->status[1] = TCPLSESSION_STATUS_SYN ;
			INIT_LIST_HEAD( & (p_tcpl_session->tcpl_packets_trace_list.this_node) );
			
			if( p_env->cmd_line_para.output_debug )
				OUTPUT_SESSION_EVENT( "ADD" , TCPLPACKET_DIRECTION , p_tcpl_session )
			
			/* 补建会话，挂到会话树上 */
			nret = LinkTcplSessionTreeNode( p_env , p_tcpl_session ) ;
			if( nret )
				return nret;
			
			/* 记录TCP分组明细 */
			nret = AddTcpPacket( p_env , pcaphdr , p_tcpl_session , TCPLPACKET_DIRECTION , tcphdr , packet_data_intercepted , packet_data_len_intercepted , packet_data_len_actually ) ;
			if( nret )
				return nret;
			
			return 0;
		}
	}
	
	return 0;
}

