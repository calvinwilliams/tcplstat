/*
 * tcplstat - TCP packets monitor and statistical tool
 * author	: calvin
 * email	: calvinwilliams@163.com
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#include "tcplstat_in.h"

int AddTcpPacket( struct TcplStatEnv *p_env , const struct pcap_pkthdr *pcaphdr , struct TcplSession *p_tcpl_session , unsigned char direction_flag , struct tcphdr *tcphdr , char *packet_data_intercepted , uint32_t packet_data_len_intercepted , uint32_t packet_data_len_actually )
{
	struct TcplPacket	*p_tcpl_packet = NULL ;
	struct TcplPacket	*p_last_tcpl_packet = NULL ;
	struct TcplPacket	*p_last_oppo_tcpl_packet = NULL ;
	
	p_tcpl_packet = (struct TcplPacket *)malloc( sizeof(struct TcplPacket) ) ;
	if( p_tcpl_packet == NULL )
	{
		printf( "*** ERROR : alloc failed , errno[%d]\n" , errno );
		exit(1);
	}
	memset( p_tcpl_packet , 0x00 , sizeof(struct TcplPacket) );
	
	COPY_TIMEVAL( p_tcpl_packet->timestamp , p_env->fixed_timestamp )
	
	if( ! list_empty( & (p_tcpl_session->tcpl_packets_list.this_node) ) )
	{
		p_last_tcpl_packet = list_last_entry( & (p_tcpl_session->tcpl_packets_list.this_node) , struct TcplPacket , this_node ) ;
		COPY_TIMEVAL( p_tcpl_packet->last_packet_elapse , p_tcpl_packet->timestamp );
		DIFF_TIMEVAL( p_tcpl_packet->last_packet_elapse , p_last_tcpl_packet->timestamp )
	}
	
	if( direction_flag == TCPLPACKET_DIRECTION )
		p_last_oppo_tcpl_packet = p_tcpl_session->p_recent_oppo_packet ;
	else
		p_last_oppo_tcpl_packet = p_tcpl_session->p_recent_packet ;
	if( p_last_oppo_tcpl_packet )
	{
		COPY_TIMEVAL( p_tcpl_packet->last_oppo_packet_elapse , p_tcpl_packet->timestamp );
		DIFF_TIMEVAL( p_tcpl_packet->last_oppo_packet_elapse , p_last_oppo_tcpl_packet->timestamp )
	}
	
	p_tcpl_packet->direction_flag = direction_flag ;
	sprintf( p_tcpl_packet->packet_flags , "%c%c%c%c%c%c" , tcphdr->syn?'S':'.' , tcphdr->fin?'F':'.' , tcphdr->psh?'P':'.' , tcphdr->ack?'A':'.' , tcphdr->rst?'R':'.' , tcphdr->urg?'U':'.' );
	
	p_tcpl_packet->packet_data_len_intercepted = packet_data_len_intercepted ;
	p_tcpl_packet->packet_data_len_actually = packet_data_len_actually ;
	if( packet_data_len_actually > 0 )
		p_tcpl_packet->packet_data_intercepted = memndup( packet_data_intercepted , packet_data_len_intercepted ) ;
	if( p_tcpl_packet == NULL )
	{
		printf( "*** ERROR : alloc tcpl_packet failed , errno[%d]\n" , errno );
		free( p_tcpl_packet );
		return -1;
	}
	
	list_add_tail( & (p_tcpl_packet->this_node) , & (p_tcpl_session->tcpl_packets_list.this_node) );
	
	if( direction_flag == TCPLPACKET_DIRECTION )
		p_tcpl_session->p_recent_packet = p_tcpl_packet ;
	else
		p_tcpl_session->p_recent_oppo_packet = p_tcpl_packet ;
	
	if( p_tcpl_session->state == TCPLSESSION_STATE_CONNECTED )
	{
		ADD_TIMEVAL( p_tcpl_session->total_packet_elapse_for_avg , p_tcpl_packet->last_packet_elapse )
		
		if( COMPARE_TIMEVAL( p_tcpl_packet->last_packet_elapse , < , p_tcpl_session->min_packet_elapse ) )
			COPY_TIMEVAL( p_tcpl_session->min_packet_elapse , p_tcpl_packet->last_packet_elapse )
		if( COMPARE_TIMEVAL( p_tcpl_packet->last_packet_elapse , > , p_tcpl_session->max_packet_elapse ) )
			COPY_TIMEVAL( p_tcpl_session->max_packet_elapse , p_tcpl_packet->last_packet_elapse )
		
		ADD_TIMEVAL( p_tcpl_session->total_oppo_packet_elapse_for_avg , p_tcpl_packet->last_oppo_packet_elapse )
		
		if( COMPARE_TIMEVAL( p_tcpl_packet->last_oppo_packet_elapse , < , p_tcpl_session->min_packet_elapse ) )
			COPY_TIMEVAL( p_tcpl_session->min_oppo_packet_elapse , p_tcpl_packet->last_oppo_packet_elapse )
		if( COMPARE_TIMEVAL( p_tcpl_packet->last_oppo_packet_elapse , > , p_tcpl_session->max_oppo_packet_elapse ) )
			COPY_TIMEVAL( p_tcpl_session->max_oppo_packet_elapse , p_tcpl_packet->last_oppo_packet_elapse )
		
		p_tcpl_session->total_packet_count++;
		p_tcpl_session->total_packet_data_len += packet_data_len_actually ;
	}
	
	return 0;
}

