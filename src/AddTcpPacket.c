/*
 * tcplstat - TCP packets monitor and statistical tool
 * author	: calvin
 * email	: calvinwilliams@163.com
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#include "tcplstat_in.h"

/* 在TCP分组有效载荷中尝试搜索SQL语言 */
static char *FindSql( char *packet_data_intercepted , uint32_t packet_data_len_intercepted , int *p_sql_len )
{
	char		*p1 = NULL ;
	char		*p2 = NULL ;
	char		*end = packet_data_intercepted + packet_data_len_intercepted - 1 ;
	
	p1 = memistr2_region( packet_data_intercepted , "SELECT" , end , 1 ) ;
	if( p1 )
	{
		p2 = memistr2_region( p1+6 , "FROM" , end , 0 ) ;
		if( p2 )
		{
			(*p_sql_len) = LengthUtilEndOfText( p2+4 , end ) ;
			(*p_sql_len) += p2-p1 + 4 ;
			return p1;
		}
	}
	
	p1 = memistr2_region( packet_data_intercepted , "UPDATE" , end , 1 ) ;
	if( p1 )
	{
		p2 = memistr2_region( p1+6 , "SET" , end , 0 ) ;
		if( p2 )
		{
			(*p_sql_len) = LengthUtilEndOfText( p2+3 , end ) ;
			(*p_sql_len) += p2-p1 + 3 ;
			return p1;
		}
	}
	
	p1 = memistr2_region( packet_data_intercepted , "INSERT" , end , 1 ) ;
	if( p1 )
	{
		p2 = memistr2_region( p1+7 , "INFO" , end , 0 ) ;
		if( p2 )
		{
			(*p_sql_len) = LengthUtilEndOfText( p2+4 , end ) ;
			(*p_sql_len) += p2-p1 + 4 ;
			return p1;
		}
	}
	
	p1 = memistr2_region( packet_data_intercepted , "DELETE" , end , 1 ) ;
	if( p1 )
	{
		p2 = memistr2_region( p1+6 , "FROM" , end , 0 ) ;
		if( p2 )
		{
			(*p_sql_len) = LengthUtilEndOfText( p2+4 , end ) ;
			(*p_sql_len) += p2-p1 + 4 ;
			return p1;
		}
	}
	
	return 0;
}

/* 新增TCP分组到明细链表中 */
int AddTcpPacket( struct TcplStatEnv *p_env , const struct pcap_pkthdr *pcaphdr , struct TcplSession *p_tcpl_session , unsigned char direction_flag , struct tcphdr *tcphdr , char *packet_data_intercepted , uint32_t packet_data_len_intercepted , uint32_t packet_data_len_actually )
{
	struct TcplPacket	*p_tcpl_packet = NULL ;
	struct TcplPacket	*p_last_tcpl_packet = NULL ;
	struct TcplPacket	*p_last_oppo_tcpl_packet = NULL ;
	
	if( p_env->unused_tcpl_packet_count == 0 )
	{
		p_tcpl_packet = (struct TcplPacket *)malloc( sizeof(struct TcplPacket) ) ;
		if( p_tcpl_packet == NULL )
		{
			fprintf( p_env->fp , "*** ERROR : alloc failed , errno[%d]\n" , errno );
			exit(1);
		}
		memset( p_tcpl_packet , 0x00 , sizeof(struct TcplPacket) );
	}
	else
	{
		REUSE_TCPL_PACKET( p_env , p_tcpl_packet )
	}
	
	COPY_TIMEVAL( p_tcpl_packet->timestamp , p_env->fixed_timestamp )
	
	/* 统计与上一个TCP分组的延迟 */
	if( ! list_empty( & (p_tcpl_session->tcpl_packets_trace_list.this_node) ) )
	{
		p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_trace_list.this_node) , struct TcplPacket , this_node ) ;
		COPY_TIMEVAL( p_tcpl_packet->last_packet_elapse , p_tcpl_packet->timestamp );
		DIFF_TIMEVAL( p_tcpl_packet->last_packet_elapse , p_last_tcpl_packet->timestamp )
	}
	
	/* 统计与上一个反向TCP分组的延迟 */
	if( direction_flag == TCPLPACKET_DIRECTION )
		p_last_oppo_tcpl_packet = p_tcpl_session->p_recent_oppo_packet ;
	else
		p_last_oppo_tcpl_packet = p_tcpl_session->p_recent_packet ;
	if( p_last_oppo_tcpl_packet )
	{
		COPY_TIMEVAL( p_tcpl_packet->last_oppo_packet_elapse , p_tcpl_packet->timestamp );
		DIFF_TIMEVAL( p_tcpl_packet->last_oppo_packet_elapse , p_last_oppo_tcpl_packet->timestamp )
	}
	
	/* 嗅探SQL语言，在下次有效荷载时统计耗时并输出 */
	if( p_env->cmd_line_para.output_sql && packet_data_len_intercepted > 0 )
	{
		if( p_tcpl_session->sql )
		{
			fprintf( p_env->fp , "Q | %s.%06ld %ld.%06ld | %.*s\n"
				, ConvDateTimeHumanReadable(p_last_oppo_tcpl_packet->timestamp.tv_sec) , p_last_oppo_tcpl_packet->timestamp.tv_usec
				, p_tcpl_packet->last_oppo_packet_elapse.tv_sec , p_tcpl_packet->last_oppo_packet_elapse.tv_usec
				, p_tcpl_session->sql_len , p_tcpl_session->sql );
			p_tcpl_session->sql = NULL ;
		}
		
		if( packet_data_intercepted )
		{
			p_tcpl_session->sql = FindSql( packet_data_intercepted , packet_data_len_intercepted , & (p_tcpl_session->sql_len) ) ;
		}
	}
	
	p_tcpl_packet->direction_flag = direction_flag ;
	sprintf( p_tcpl_packet->packet_flags , "%c%c%c%c%c%c" , tcphdr->syn?'S':'.' , tcphdr->fin?'F':'.' , tcphdr->psh?'P':'.' , tcphdr->ack?'A':'.' , tcphdr->rst?'R':'.' , tcphdr->urg?'U':'.' );
	
	p_tcpl_packet->packet_data_len_intercepted = packet_data_len_intercepted ;
	p_tcpl_packet->packet_data_len_actually = packet_data_len_actually ;
	if( packet_data_len_actually > 0 )
		p_tcpl_packet->packet_data_intercepted = memndup( packet_data_intercepted , packet_data_len_intercepted ) ;
	if( p_tcpl_packet == NULL )
	{
		fprintf( p_env->fp , "*** ERROR : alloc tcpl_packet failed , errno[%d]\n" , errno );
		free( p_tcpl_packet );
		return -1;
	}
	
	/* TCP分组明细挂接到链表中 */
	list_add_tail( & (p_tcpl_packet->this_node) , & (p_tcpl_session->tcpl_packets_trace_list.this_node) );
	
	if( direction_flag == TCPLPACKET_DIRECTION )
		p_tcpl_session->p_recent_packet = p_tcpl_packet ;
	else
		p_tcpl_session->p_recent_oppo_packet = p_tcpl_packet ;
	
	/* 如果不是握手和分手，统计正向/反向的最小、平均和、最大延迟 */
	if( p_tcpl_session->state == TCPLSESSION_STATE_CONNECTED )
	{
		ADD_TIMEVAL( p_tcpl_session->total_packet_elapse_for_avg , p_tcpl_packet->last_packet_elapse )
		
		if( p_tcpl_session->min_packet_flag == 0 || COMPARE_TIMEVAL( p_tcpl_packet->last_packet_elapse , < , p_tcpl_session->min_packet_elapse ) )
		{
			p_tcpl_session->min_packet_flag = 1 ;
			COPY_TIMEVAL( p_tcpl_session->min_packet_elapse , p_tcpl_packet->last_packet_elapse )
		}
		if( p_tcpl_session->max_packet_flag == 0 || COMPARE_TIMEVAL( p_tcpl_packet->last_packet_elapse , > , p_tcpl_session->max_packet_elapse ) )
		{
			p_tcpl_session->max_packet_flag = 1 ;
			COPY_TIMEVAL( p_tcpl_session->max_packet_elapse , p_tcpl_packet->last_packet_elapse )
		}
		
		ADD_TIMEVAL( p_tcpl_session->total_oppo_packet_elapse_for_avg , p_tcpl_packet->last_oppo_packet_elapse )
		
		if( p_tcpl_session->min_oppo_packet_flag == 0 || COMPARE_TIMEVAL( p_tcpl_packet->last_oppo_packet_elapse , < , p_tcpl_session->min_oppo_packet_elapse ) )
		{
			p_tcpl_session->min_oppo_packet_flag = 1 ;
			COPY_TIMEVAL( p_tcpl_session->min_oppo_packet_elapse , p_tcpl_packet->last_oppo_packet_elapse )
		}
		if( p_tcpl_session->max_oppo_packet_flag == 0 || COMPARE_TIMEVAL( p_tcpl_packet->last_oppo_packet_elapse , > , p_tcpl_session->max_oppo_packet_elapse ) )
		{
			p_tcpl_session->max_oppo_packet_flag = 1 ;
			COPY_TIMEVAL( p_tcpl_session->max_oppo_packet_elapse , p_tcpl_packet->last_oppo_packet_elapse )
		}
		
		p_tcpl_session->total_packet_trace_count++;
		p_tcpl_session->total_packet_trace_data_len += packet_data_len_actually ;
	}
	
	if( p_env->cmd_line_para.output_debug )
		OUTPUT_PACKET_EVENT( p_tcpl_session , p_tcpl_packet )
	
	return 0;
}

