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

#define _DEBUG		0

struct TcplAddrHumanReadable
{
	char		src_ip[ 15 + 1 ] ;
	char		dst_ip[ 15 + 1 ] ;
	int		src_port ;
	int		dst_port ;
} ;

#define SET_TCPL_SESSION_ID(_tcpl_session_id_,_client_ip_,_client_port_,_server_ip_,_server_port_) \
	(_tcpl_session_id_).client_ip.s_addr = _client_ip_.s_addr ; \
	(_tcpl_session_id_).client_port = _client_port_ ; \
	(_tcpl_session_id_).server_ip.s_addr = _server_ip_.s_addr ; \
	(_tcpl_session_id_).server_port = _server_port_ ; \

#define COPY_TIMEVAL(_timeval1_,_timeval2_) \
	(_timeval1_).tv_sec = _timeval2_.tv_sec ; \
	(_timeval1_).tv_usec = _timeval2_.tv_usec ; \

#define DIFF_TIMEVAL(_timeval1_,_timeval2_) \
	(_timeval1_).tv_sec -= (_timeval2_).tv_sec ; \
	(_timeval1_).tv_usec -= (_timeval2_).tv_usec ; \
	while( (_timeval1_).tv_usec < 0 ) \
	{ \
		(_timeval1_).tv_usec += 1000000 ; \
		(_timeval1_).tv_sec--; \
	} \

struct TcplSessionId
{
	struct in_addr		client_ip ;
	uint16_t		client_port ;
	struct in_addr		server_ip ;
	uint16_t		server_port ;
} ;

#define TCPLPACKET_FLAG_UNKNOW	0
#define TCPLPACKET_FLAG_SYN	1
#define TCPLPACKET_FLAG_FIN	2
#define TCPLPACKET_FLAG_DAT	3
#define TCPLPACKET_FLAG_ACK	4

struct TcplPacket
{
	struct timeval		timestamp ;
	int			direct_flag ;
	struct timeval		diff_opposite_direction ;
	
	int			packet_flag ;
	uint32_t		packet_data_len ;
	char			*packet_data ;
	
	struct list_head	this_node ;
} ;

#define TCPLSESSION_STATUS_CLOSED	0
#define TCPLSESSION_STATUS_SYN		1
#define TCPLSESSION_STATUS_FIN		2

struct TcplSession
{
	struct TcplSessionId		tcpl_session_id ;
	struct TcplAddrHumanReadable	tcpl_addr_hr ;
	
	struct timeval			begin_timestamp ;
	int				status[ 2 ] ;
	
	struct TcplPacket		tcpl_packets_list ;
	struct TcplPacket		*p_recent_sent_packet ;
	struct TcplPacket		*p_recent_recv_packet ;
	
	struct rb_node			tcplsession_rbnode ;
} ;

struct CommandLineParameters
{
	char			*network_interface ;
	char			*filter_string ;
	int			output_level ;
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
	
	struct rb_root			tcplsessions_rbtree ;
} ;

int LinkTcplSessionTreeNode( struct TcplStatEnv *p_tcpl_stat_env , struct TcplSession *p_tcpl_session );
struct TcplSession *QueryTcplSessionTreeNode( struct TcplStatEnv *p_tcpl_stat_env , struct TcplSession *p_tcpl_session );
void UnlinkTcplSessionTreeNode( struct TcplStatEnv *p_tcpl_stat_env , struct TcplSession *p_tcpl_session );
struct TcplSession *TravelTcplSessionTreeNode( struct TcplStatEnv *p_tcpl_stat_env , struct TcplSession *p_tcpl_session );
void DestroyTcplSessionTree( struct TcplStatEnv *p_tcpl_stat_env );

char *memndup( const char *s, size_t n );
int DumpBuffer( char *pathfilename , int buf_len , void *buf );

void PcapCallback( u_char *args , const struct pcap_pkthdr *header , const u_char *packet );

int ProcessTcpPacket( struct TcplStatEnv *p_env , const struct pcap_pkthdr *pcaphdr , struct ether_header *etherhdr , struct ip *iphdr , struct tcphdr *tcphdr , struct TcplAddrHumanReadable *p_tcpl_addr_hr , uint32_t packet_data_len , char *packet_data );

#endif

