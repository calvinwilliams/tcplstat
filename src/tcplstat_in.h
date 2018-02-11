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
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>

#if ( defined __linux__ )
#include <net/ethernet.h>
#elif ( defined _AIX )
#include <netinet/if_ether.h>
#endif

#include "pcap.h"
#if ( defined __linux__ )
#include "pcap/sll.h"
#elif ( defined _AIX )
#undef _AIX
#include "net/bpf.h"
#define _AIX
#endif

#include "list.h"
#include "rbtree.h"

/* 公共宏 */
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

/* 以太网分组头 */
struct NetinetEthernetHeader
{
	unsigned char	_ether_dhost[ 6 ] ;
	unsigned char	_ether_shost[ 6 ] ;
	unsigned short	_ether_type ;
} ;

/* IP分组头 */
struct NetinetIpHeader
{
	unsigned char	_ip_vhl ;
	unsigned char	_ip_tos ;
	unsigned short	_ip_len ;
	unsigned short	_ip_id ;
	unsigned short	_ip_off ;
#define IP_RF		0x8000
#define IP_DF		0x4000
#define IP_MF		0x2000
#define IP_OFFMASK	0x1fff
	unsigned char	_ip_ttl ;
	unsigned char	_ip_p ;
	unsigned short	_ip_sum ;
	struct in_addr	_ip_src ;
	struct in_addr	_ip_dst ;
} ;

#define IP_HL(ip)	(((ip)->_ip_vhl) & 0x0f)
#define IP_V(ip)	(((ip)->_ip_vhl) >> 4)

/* TCP分组头 */
struct NetinetTcpHeader
{
	unsigned short	_th_sport ;
	unsigned short	_th_dport ;
	unsigned int	_th_seq ;
	unsigned int	_th_ack ;
	unsigned char	_th_offx2 ;
#define TH_OFF(th)	(((th)->_th_offx2 & 0xf0) >> 4)
	unsigned char	_th_flags ;
#define TH_FIN		0x01
#define TH_SYN		0x02
#define TH_RST		0x04
#define TH_PSH		0x08
#define TH_ACK		0x10
#define TH_URG		0x20
#define TH_ECE		0x40
#define TH_CWR		0x80
#define TH_FLAGS	(TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define TH_FLAG(tcp,flag)	((((tcp)->_th_flags)&flag)?1:0)
	unsigned short	_th_win ;
	unsigned short	_th_sum ;
	unsigned short	_th_urp ;
} ;

/* 网络地址信息 */
#define SET_TCPL_SESSION_ID(_tcpl_session_id_,_client_ip_,_client_port_,_server_ip_,_server_port_) \
	{ \
		memset( & (_tcpl_session_id_) , 0x00 , sizeof(struct TcplSessionId) ); \
		(_tcpl_session_id_).client_ip.s_addr = _client_ip_.s_addr ; \
		(_tcpl_session_id_).client_port = _client_port_ ; \
		(_tcpl_session_id_).server_ip.s_addr = _server_ip_.s_addr ; \
		(_tcpl_session_id_).server_port = _server_port_ ; \
	} \

struct TcplAddrHumanReadable
{
	char		src_mac[ 17 + 1 ] ;
	char		dst_mac[ 17 + 1 ] ;
	char		src_ip[ 15 + 1 ] ;
	char		dst_ip[ 15 + 1 ] ;
	int		src_port ;
	int		dst_port ;
} ;

/* 时间戳操作宏 */
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

/* TCP分组 */
#define TCPLPACKET_DIRECTION		1
#define TCPLPACKET_OPPO_DIRECTION	2

#define TCPLPACKET_FLAG_UNKNOW	0
#define TCPLPACKET_FLAG_SYN	1
#define TCPLPACKET_FLAG_FIN	2
#define TCPLPACKET_FLAG_DAT	3
#define TCPLPACKET_FLAG_ACK	4

#define OUTPUT_PACKET_EVENT(_p_tcpl_session_,_p_tcpl_packet_) \
	{ \
		fprintf( p_env->fp , "d |     ADD PACKET OF SESSION[%p] | %s.%06ld | %ld.%06ld %ld.%06ld | [%s:%d]%s[%s:%d] %s %d\n" \
			, (_p_tcpl_session_) \
			, ConvDateTimeHumanReadable((_p_tcpl_packet_)->timestamp.tv_sec) , (_p_tcpl_packet_)->timestamp.tv_usec \
			, (_p_tcpl_packet_)->last_packet_elapse.tv_sec , (_p_tcpl_packet_)->last_packet_elapse.tv_usec \
			, (_p_tcpl_packet_)->last_oppo_packet_elapse.tv_sec , (_p_tcpl_packet_)->last_oppo_packet_elapse.tv_usec \
			, (_p_tcpl_session_)->tcpl_addr_hr.src_ip , (_p_tcpl_session_)->tcpl_addr_hr.src_port , (_p_tcpl_packet_)->direction_flag==TCPLPACKET_DIRECTION?"->":"<-" , (_p_tcpl_session_)->tcpl_addr_hr.dst_ip , (_p_tcpl_session_)->tcpl_addr_hr.dst_port \
			, (_p_tcpl_packet_)->packet_flags \
			, (_p_tcpl_packet_)->packet_data_len_actually ); \
	} \

#define RECYCLING_TCPL_PACKET(_p_env_,_p_tcpl_packet_) \
	{ \
		list_del( & ((_p_tcpl_packet_)->this_node) ); \
		if( (_p_tcpl_packet_)->packet_data_intercepted ) \
			free( (_p_tcpl_packet_)->packet_data_intercepted ); \
		memset( (_p_tcpl_packet_) , 0x00 , sizeof(struct TcplPacket) ); \
		\
		list_add_tail( & ((_p_tcpl_packet_)->this_node) , & ((_p_env_)->unused_tcpl_packet.this_node) ); \
		(_p_env_)->unused_tcpl_packet_count++; \
		\
		if( (_p_env_)->cmd_line_para.output_debug ) \
		{ \
			fprintf( p_env->fp , "d | REUSE TCPL PACKET[%p]\n" , (_p_tcpl_packet_) ); \
		} \
	} \

#define REUSE_TCPL_PACKET(_p_env_,_p_tcpl_packet_) \
	{ \
		(_p_tcpl_packet_) = list_first_entry( & ((_p_env_)->unused_tcpl_packet.this_node) , struct TcplPacket , this_node ) ; \
		list_del( & ((_p_tcpl_packet_)->this_node) ); \
		memset( (_p_tcpl_packet_) , 0x00 , sizeof(struct TcplPacket) ); \
		(_p_env_)->unused_tcpl_packet_count--; \
		\
		if( (_p_env_)->cmd_line_para.output_debug ) \
		{ \
			fprintf( p_env->fp , "d | RECYCLING TCPL PACKET[%p]\n" , (_p_tcpl_packet_) ); \
		} \
	} \

#define DELETE_TCPL_PACKET(_p_env_,_p_tcpl_packet_) \
	{ \
		if( (_p_env_)->cmd_line_para.output_debug ) \
		{ \
			fprintf( p_env->fp , "d | DELETE TCPL PACKET[%p]\n" , (_p_tcpl_packet_) ); \
		} \
		list_del( & ((_p_tcpl_packet_)->this_node) ); \
		if( (_p_tcpl_packet_)->packet_data_intercepted ) \
			free( (_p_tcpl_packet_)->packet_data_intercepted ); \
		free( (_p_tcpl_packet_) ); \
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
	
	unsigned char		is_lock ;
	
	struct list_head	this_node ;
} ;

/* 会话ID结构 */
struct TcplSessionId
{
	struct in_addr		client_ip ;
	uint16_t		client_port ;
	struct in_addr		server_ip ;
	uint16_t		server_port ;
} ;

/* TCP会话 */
#define TCPLSESSION_MAX_PACKET_TRACE_COUNT	100

#define TCPLSESSION_STATE_DISCONNECTED		0
#define TCPLSESSION_STATE_CONNECTING		1
#define TCPLSESSION_STATE_CONNECTED		2
#define TCPLSESSION_STATE_DISCONNECTING		3

#define TCPLSESSION_STATUS_CLOSED		0
#define TCPLSESSION_STATUS_SYN			'S'
#define TCPLSESSION_STATUS_FIN			'F'

#define TCPLSESSION_DISCONNECT_WAITFOR		0
#define TCPLSESSION_DISCONNECT_DIRECTION	1
#define TCPLSESSION_DISCONNECT_OPPO_DIRECTION	2

#define OUTPUT_SESSION_EVENT(_action_,_direction_flag_,_p_tcpl_session_) \
	{ \
		fprintf( p_env->fp , "d |     %s SESSION[%p] | %s.%06ld [%s:%d]%s[%s:%d] | %s | %c%c\n" \
			, (_action_) , (_p_tcpl_session_) \
			, ConvDateTimeHumanReadable((_p_tcpl_session_)->begin_timestamp.tv_sec) , (_p_tcpl_session_)->begin_timestamp.tv_usec \
			, (_p_tcpl_session_)->tcpl_addr_hr.src_ip , (_p_tcpl_session_)->tcpl_addr_hr.src_port , (_direction_flag_)==TCPLPACKET_DIRECTION?"->":"<-" , (_p_tcpl_session_)->tcpl_addr_hr.dst_ip , (_p_tcpl_session_)->tcpl_addr_hr.dst_port \
			, _g_tcplstat_tcplsession_state[(_p_tcpl_session_)->state] \
			, (_p_tcpl_session_)->status[0]?(_p_tcpl_session_)->status[0]:'.' , (_p_tcpl_session_)->status[1]?(_p_tcpl_session_)->status[1]:'.' ); \
	} \

#define RECYCLING_TCPL_SESSION(_p_env_,_p_tcpl_session_) \
	{ \
		memset( (_p_tcpl_session_) , 0x00 , sizeof(struct TcplSession) ); \
		INIT_LIST_HEAD( & ((_p_tcpl_session_)->tcpl_packets_trace_list.this_node) ); \
		\
		list_add_tail( & ((_p_tcpl_session_)->this_node) , & ((_p_env_)->unused_tcpl_session.this_node) ); \
		(_p_env_)->unused_tcpl_session_count++; \
		\
		if( (_p_env_)->cmd_line_para.output_debug ) \
		{ \
			fprintf( p_env->fp , "d | RECYCLING TCPL SESSION[%p]\n" , (_p_tcpl_session_) ); \
		} \
	} \

#define REUSE_TCPL_SESSION(_p_env_,_p_tcpl_session_) \
	{ \
		(_p_tcpl_session_) = list_first_entry( & ((_p_env_)->unused_tcpl_session.this_node) , struct TcplSession , this_node ) ; \
		list_del( & ((_p_tcpl_session_)->this_node) ); \
		memset( (_p_tcpl_session_) , 0x00 , sizeof(struct TcplSession) ); \
		(_p_env_)->unused_tcpl_session_count--; \
		\
		if( (_p_env_)->cmd_line_para.output_debug ) \
		{ \
			fprintf( p_env->fp , "d | REUSE TCPL SESSION[%p]\n" , (_p_tcpl_session_) ); \
		} \
	} \

#define DELETE_TCPL_SESSION(_p_env_,_p_tcpl_session_) \
	{ \
		if( (_p_env_)->cmd_line_para.output_debug ) \
		{ \
			fprintf( p_env->fp , "d | DELETE TCPL SESSION[%p]\n" , (_p_tcpl_session_) ); \
		} \
		free( (_p_tcpl_session_) ); \
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
	
	struct TcplPacket		tcpl_packets_trace_list ;
	struct TcplPacket		*p_recent_packet ;
	struct TcplPacket		*p_recent_oppo_packet ;
	
	uint32_t			total_packet_trace_count ;
	uint32_t			total_packet_trace_data_len ;
	
	unsigned char			continue_trace_flag ;
	
	char				*sql ;
	int				sql_len ;
	
	char				*http_first_line ;
	int				http_first_line_len ;
	
	struct list_head		this_node ;
	struct rb_node			tcplsession_rbnode ;
} ;

/* 命令行参数 */
struct CommandLineParameters
{
	char			*network_interface ;
	char			*filter_string ;
	int			max_packet_trace_count ;
	unsigned char		output_debug ;
	unsigned char		output_event ;
	unsigned char		output_session ;
	unsigned char		output_session_packet ;
	unsigned char		output_session_packet_data ;
	unsigned char		output_sql ;
	unsigned char		output_http ;
	char			*log_pathfilename ;
} ;

/* 环境结构 */
#define PENV_MAX_UNUSED_TCPLSESSION_COUNT	10
#define PENV_MAX_UNUSED_TCPLPACKET_COUNT	100

struct TcplStatEnv
{
	struct CommandLineParameters	cmd_line_para ;
	FILE				*fp ;
	
	char				pcap_errbuf[ PCAP_ERRBUF_SIZE ] ;
	pcap_t				*pcap ;
	struct bpf_program		pcap_filter ;
	
	struct timeval			fixed_timestamp ;
	struct timeval			last_fixed_timestamp ;
	
	struct rb_root			tcpl_sessions_rbtree ;
	
	struct TcplSession		unused_tcpl_session ;
	int				unused_tcpl_session_count ;
	struct TcplPacket		unused_tcpl_packet ;
	int				unused_tcpl_packet_count ;
} ;

extern struct TcplStatEnv	*g_p_env ;

/* 会话结构树 */
int LinkTcplSessionTreeNode( struct TcplStatEnv *p_tcpl_stat_env , struct TcplSession *p_tcpl_session );
struct TcplSession *QueryTcplSessionTreeNode( struct TcplStatEnv *p_tcpl_stat_env , struct TcplSession *p_tcpl_session );
void UnlinkTcplSessionTreeNode( struct TcplStatEnv *p_tcpl_stat_env , struct TcplSession *p_tcpl_session );
struct TcplSession *TravelTcplSessionTreeNode( struct TcplStatEnv *p_tcpl_stat_env , struct TcplSession *p_tcpl_session );
void DestroyTcplSessionTree( struct TcplStatEnv *p_tcpl_stat_env );

/* 公共函数 */
char *memndup( const char *s, size_t n );
char *memistr2_region( char *p_curr , char *find , char *end , unsigned char binary_mode );
int LengthUtilEndOfText( char *p_curr , char *end );
char *ConvDateTimeHumanReadable( time_t tt );
int DumpBuffer( FILE *fp , char *indentation , char *pathfilename , int buf_len , void *buf );

/* PCAP回调函数 */
void PcapCallback( unsigned char *args , const struct pcap_pkthdr *header , const unsigned char *packet );

/* 处理TCP分组 */
int ProcessTcpPacket( struct TcplStatEnv *p_env , const struct pcap_pkthdr *pcaphdr , struct NetinetEthernetHeader *etherhdr , struct NetinetIpHeader *iphdr , struct NetinetTcpHeader *tcphdr , struct TcplAddrHumanReadable *p_tcpl_addr_hr , char *packet_data_intercepted , uint32_t packet_data_len_intercepted , uint32_t packet_data_len_actually );

/* 增加TCP分组 */
int AddTcpPacket( struct TcplStatEnv *p_env , const struct pcap_pkthdr *pcaphdr , struct TcplSession *p_tcpl_session , unsigned char direction_flag , struct NetinetTcpHeader *tcphdr , char *packet_data_intercepted , uint32_t packet_data_len_intercepted , uint32_t packet_data_len_actually );

/* 输出TCP会话和包明细 */
void OutputTcplSession( struct TcplStatEnv *p_env , const struct pcap_pkthdr *pcaphdr , struct TcplSession *p_tcpl_session );

#endif

