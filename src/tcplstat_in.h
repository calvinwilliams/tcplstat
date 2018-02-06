/*
 * tcplstat - TCP packets monitor and statistical tool
 * author	: calvin
 * email	: calvinwilliams@163.com
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#ifndef _H_TCPLSTAT_
#define _H_TCPLSTAT_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>

#include "pcap/pcap.h"
#include "pcap/sll.h"

#include "list.h"
#include "rbtree.h"

#ifndef STRCMP
#define STRCMP(_a_,_C_,_b_) ( strcmp(_a_,_b_) _C_ 0 )
#define STRNCMP(_a_,_C_,_b_,_n_) ( strncmp(_a_,_b_,_n_) _C_ 0 )
#endif

#ifndef STRICMP
#ifdef _TYPE_OS_WINDOWS_
#define STRICMP(_a_,_C_,_b_) ( stricmp(_a_,_b_) _C_ 0 )
#define STRNICMP(_a_,_C_,_b_,_n_) ( strnicmp(_a_,_b_,_n_) _C_ 0 )
#endif
#if ( defined _TYPE_OS_AIX_ ) | ( defined _TYPE_OS_SCO_ ) | ( defined _TYPE_OS_LINUX_ )
#define STRICMP(_a_,_C_,_b_) ( strcasecmp(_a_,_b_) _C_ 0 )
#define STRNICMP(_a_,_C_,_b_,_n_) ( strncasecmp(_a_,_b_,_n_) _C_ 0 )
#endif
#endif

#ifndef MEMCMP
#define MEMCMP(_a_,_C_,_b_,_n_) ( memcmp(_a_,_b_,_n_) _C_ 0 )
#endif

#define SIZE_ETHERNET		14

struct TcplAddrHumanReadable
{
	char		src_mac[ 17 + 1 ] ;
	char		dst_mac[ 17 + 1 ] ;
	char		src_ip[ 15 + 1 ] ;
	char		dst_ip[ 15 + 1 ] ;
	int		src_port ;
	int		dst_port ;
} ;

#define SET_TCPL_SESSION_ID(_tcpl_session_id_,_client_ip_,_client_port_,_server_ip_,_server_port_) \
	{ \
		memset( & (_tcpl_session_id_) , 0x00 , sizeof(struct TcplSessionId) ); \
		(_tcpl_session_id_).client_ip.s_addr = _client_ip_.s_addr ; \
		(_tcpl_session_id_).client_port = _client_port_ ; \
		(_tcpl_session_id_).server_ip.s_addr = _server_ip_.s_addr ; \
		(_tcpl_session_id_).server_port = _server_port_ ; \
	} \

#define COPY_TIMEVAL(_timeval1_,_timeval2_) \
	{ \
		(_timeval1_).tv_sec = (_timeval2_).tv_sec ; \
		(_timeval1_).tv_usec = (_timeval2_).tv_usec ; \
	} \

#define DIFF_TIMEVAL(_timeval1_,_timeval2_) \
	{ \
		(_timeval1_).tv_sec -= (_timeval2_).tv_sec ; \
		(_timeval1_).tv_usec -= (_timeval2_).tv_usec ; \
		while( (_timeval1_).tv_usec < 0 ) \
		{ \
			(_timeval1_).tv_usec += 1000000 ; \
			(_timeval1_).tv_sec--; \
		} \
	} \

#define ADD_TIMEVAL(_timeval1_,_timeval2_) \
	{ \
		(_timeval1_).tv_sec += (_timeval2_).tv_sec ; \
		(_timeval1_).tv_usec += (_timeval2_).tv_usec ; \
		while( (_timeval1_).tv_usec >= 1000000 ) \
		{ \
			(_timeval1_).tv_usec -= 1000000 ; \
			(_timeval1_).tv_sec++; \
		} \
	} \

#define COMPARE_TIMEVAL(_timeval1_,_compare_,_timeval2_) \
	( \
		( \
			(_timeval1_).tv_sec < (_timeval2_).tv_sec ? -1 : ( \
				(_timeval1_).tv_sec > (_timeval2_).tv_sec ? 1 : ( \
					(_timeval1_).tv_usec < (_timeval2_).tv_usec ? -1 : ( \
						(_timeval1_).tv_usec > (_timeval2_).tv_usec ? 1 : 0 \
					) \
				) \
			) \
		) _compare_ 0\
	) \

struct TcplSessionId
{
	struct in_addr		client_ip ;
	uint16_t		client_port ;
	struct in_addr		server_ip ;
	uint16_t		server_port ;
} ;

#define TCPLPACKET_DIRECTION		1
#define TCPLPACKET_OPPO_DIRECTION	2

#define TCPLPACKET_FLAG_UNKNOW	0
#define TCPLPACKET_FLAG_SYN	1
#define TCPLPACKET_FLAG_FIN	2
#define TCPLPACKET_FLAG_DAT	3
#define TCPLPACKET_FLAG_ACK	4

#define OUTPUT_PACKET_EVENT(_p_tcpl_session_,_p_tcpl_packet_) \
	{ \
		printf( "d |     ADD PACKET OF SESSION[%p] | %ld.%06ld | %ld.%06ld %ld.%06ld | [%s:%d]%s[%s:%d] %s %d\n" \
			, (_p_tcpl_session_) \
			, (_p_tcpl_packet_)->timestamp.tv_sec , (_p_tcpl_packet_)->timestamp.tv_usec \
			, (_p_tcpl_packet_)->last_packet_elapse.tv_sec , (_p_tcpl_packet_)->last_packet_elapse.tv_usec \
			, (_p_tcpl_packet_)->last_oppo_packet_elapse.tv_sec , (_p_tcpl_packet_)->last_oppo_packet_elapse.tv_usec \
			, (_p_tcpl_session_)->tcpl_addr_hr.src_ip , (_p_tcpl_session_)->tcpl_addr_hr.src_port , (_p_tcpl_packet_)->direction_flag==TCPLPACKET_DIRECTION?"->":"<-" , (_p_tcpl_session_)->tcpl_addr_hr.dst_ip , (_p_tcpl_session_)->tcpl_addr_hr.dst_port \
			, (_p_tcpl_packet_)->packet_flags \
			, (_p_tcpl_packet_)->packet_data_len_actually ); \
	} \

struct TcplPacket
{
	struct timeval		timestamp ;
	
	struct timeval		last_packet_elapse ;
	struct timeval		last_oppo_packet_elapse ;
	
	unsigned char		direction_flag ;
	char			packet_flags[ 6 + 1 ] ; /*SFPARU*/
	
	char			*packet_data_intercepted ;
	uint32_t		packet_data_len_intercepted ;
	uint32_t		packet_data_len_actually ;
	
	struct list_head	this_node ;
} ;

#define TCPLSESSION_STATE_DISCONNECTED	0
#define TCPLSESSION_STATE_CONNECTING	1
#define TCPLSESSION_STATE_CONNECTED	2
#define TCPLSESSION_STATE_DISCONNECTING	3

#define TCPLSESSION_STATUS_CLOSED	0
#define TCPLSESSION_STATUS_SYN		'S'
#define TCPLSESSION_STATUS_FIN		'F'

#define TCPLSESSION_DISCONNECT_WAITFOR		0
#define TCPLSESSION_DISCONNECT_DIRECTION	1
#define TCPLSESSION_DISCONNECT_OPPO_DIRECTION	2

#define OUTPUT_SESSION_EVENT(_action_,_direction_flag_,_p_tcpl_session_) \
	{ \
		printf( "d |     %s SESSION[%p] | [%s:%d]%s[%s:%d] | %s | %c%c\n" \
			, (_action_) , (_p_tcpl_session_) \
			, (_p_tcpl_session_)->tcpl_addr_hr.src_ip , (_p_tcpl_session_)->tcpl_addr_hr.src_port , (_direction_flag_)==TCPLPACKET_DIRECTION?"->":"<-" , (_p_tcpl_session_)->tcpl_addr_hr.dst_ip , (_p_tcpl_session_)->tcpl_addr_hr.dst_port \
			, _g_tcplstat_tcplsession_state[(_p_tcpl_session_)->state] \
			, (_p_tcpl_session_)->status[0]?(_p_tcpl_session_)->status[0]:'.' , (_p_tcpl_session_)->status[1]?(_p_tcpl_session_)->status[1]:'.' ); \
	} \

struct TcplSession
{
	struct TcplSessionId		tcpl_session_id ;
	struct TcplAddrHumanReadable	tcpl_addr_hr ;
	
	struct timeval			begin_timestamp ;
	
	struct timeval			wait_for_second_syn_and_first_ack_elapse ;
	struct timeval			wait_for_after_syn_and_second_ack_elapse ;
	
	unsigned char			min_packet_flag ;
	unsigned char			max_packet_flag ;
	unsigned char			min_oppo_packet_flag ;
	unsigned char			max_oppo_packet_flag ;
	
	struct timeval			min_packet_elapse ;
	struct timeval			max_packet_elapse ;
	struct timeval			total_packet_elapse_for_avg ;
	struct timeval			min_oppo_packet_elapse ;
	struct timeval			max_oppo_packet_elapse ;
	struct timeval			total_oppo_packet_elapse_for_avg ;
	
	struct timeval			wait_for_first_fin_elapse ;
	struct timeval			wait_for_second_fin_and_first_ack_elapse ;
	struct timeval			wait_for_second_ack_elapse ;
	
	unsigned char			state ;
	unsigned char			status[ 2 ] ;
	unsigned char			disconnect_direction ;
	
	struct TcplPacket		tcpl_packets_list ;
	struct TcplPacket		*p_recent_packet ;
	struct TcplPacket		*p_recent_oppo_packet ;
	
	uint32_t			total_packet_count ;
	uint32_t			total_packet_data_len ;
	
	char				*sql ;
	int				sql_len ;
	
	struct rb_node			tcplsession_rbnode ;
} ;

struct CommandLineParameters
{
	char			*network_interface ;
	char			*filter_string ;
	unsigned char		output_debug ;
	unsigned char		output_event ;
	unsigned char		output_session ;
	unsigned char		output_session_packet ;
	unsigned char		output_session_packet_data ;
	unsigned char		output_sql ;
} ;

#define OUTPUT_LEVEL_0		0
#define OUTPUT_LEVEL_1		1
#define OUTPUT_LEVEL_2		2
#define OUTPUT_LEVEL_3		3

struct TcplStatEnv
{
	struct CommandLineParameters	cmd_line_para ;
	
	char				pcap_errbuf[ PCAP_ERRBUF_SIZE ] ;
	pcap_t				*pcap ;
	struct bpf_program		pcap_filter ;
	
	struct timeval			fixed_timestamp ;
	struct timeval			last_fixed_timestamp ;
	
	struct rb_root			tcplsessions_rbtree ;
} ;

int LinkTcplSessionTreeNode( struct TcplStatEnv *p_tcpl_stat_env , struct TcplSession *p_tcpl_session );
struct TcplSession *QueryTcplSessionTreeNode( struct TcplStatEnv *p_tcpl_stat_env , struct TcplSession *p_tcpl_session );
void UnlinkTcplSessionTreeNode( struct TcplStatEnv *p_tcpl_stat_env , struct TcplSession *p_tcpl_session );
struct TcplSession *TravelTcplSessionTreeNode( struct TcplStatEnv *p_tcpl_stat_env , struct TcplSession *p_tcpl_session );
void DestroyTcplSessionTree( struct TcplStatEnv *p_tcpl_stat_env );

char *memndup( const char *s, size_t n );
char *memistr2_region( char *p_curr , char *find , char *end , unsigned char binary_mode );
int LengthUtilEndOfText( char *p_curr , char *end );
int DumpBuffer( char *indentation , char *pathfilename , int buf_len , void *buf );

void PcapCallback( u_char *args , const struct pcap_pkthdr *header , const u_char *packet );

int ProcessTcpPacket( struct TcplStatEnv *p_env , const struct pcap_pkthdr *pcaphdr , struct ether_header *etherhdr , struct ip *iphdr , struct tcphdr *tcphdr , struct TcplAddrHumanReadable *p_tcpl_addr_hr , char *packet_data_intercepted , uint32_t packet_data_len_intercepted , uint32_t packet_data_len_actually );
int AddTcpPacket( struct TcplStatEnv *p_env , const struct pcap_pkthdr *pcaphdr , struct TcplSession *p_tcpl_session , unsigned char direction_flag , struct tcphdr *tcphdr , char *packet_data_intercepted , uint32_t packet_data_len_intercepted , uint32_t packet_data_len_actually );
void DumpTcplSession( struct TcplStatEnv *p_env , const struct pcap_pkthdr *pcaphdr , struct TcplSession *p_tcpl_session );

#endif

