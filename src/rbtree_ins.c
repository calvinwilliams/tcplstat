/*
 * tcplstat - TCP packets monitor and statistical tool
 * author	: calvin
 * email	: calvinwilliams@163.com
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#include "tcplstat_in.h"

#include "rbtree_tpl.h"

funcCompareRbTreeNodeEntry CompareTcplSessionTreeNodeEntry ;
int CompareTcplSessionTreeNodeEntry( void *pv1 , void *pv2 )
{
	struct TcplSession	*p_tcpl_session_1 = (struct TcplSession *)pv1 ;
	struct TcplSession	*p_tcpl_session_2 = (struct TcplSession *)pv2 ;
	
	if( MEMCMP( & (p_tcpl_session_1->tcpl_session_id) , < , & (p_tcpl_session_2->tcpl_session_id) , sizeof(struct TcplSessionId) ) )
		return -1;
	else if( MEMCMP( & (p_tcpl_session_1->tcpl_session_id) , > , & (p_tcpl_session_2->tcpl_session_id) , sizeof(struct TcplSessionId) ) )
		return 1;
	else
		return 0;
}

funcFreeRbTreeNodeEntry FreeTcplSessionTreeNodeEntry ;
void FreeTcplSessionTreeNodeEntry( void *pv )
{
	struct TcplStatEnv	*p_env = g_p_env ;
	struct TcplSession	*p_tcpl_session = (struct TcplSession *)pv ;
	
	struct TcplPacket	*p_tcpl_packet = NULL ;
	struct TcplPacket	*p_next_tcpl_packet = NULL ;
	
	list_for_each_entry_safe( p_tcpl_packet , p_next_tcpl_packet , & (p_tcpl_session->tcpl_packets_trace_list.this_node) , struct TcplPacket , this_node )
	{
		DELETE_TCPL_PACKET( p_env , p_tcpl_packet )
	}
	
	DELETE_TCPL_SESSION( p_env , p_tcpl_session )
	
	return;
}

LINK_RBTREENODE( LinkTcplSessionTreeNode , struct TcplStatEnv , tcpl_sessions_rbtree , struct TcplSession , tcplsession_rbnode , CompareTcplSessionTreeNodeEntry )
QUERY_RBTREENODE( QueryTcplSessionTreeNode , struct TcplStatEnv , tcpl_sessions_rbtree , struct TcplSession , tcplsession_rbnode , CompareTcplSessionTreeNodeEntry )
UNLINK_RBTREENODE( UnlinkTcplSessionTreeNode , struct TcplStatEnv , tcpl_sessions_rbtree , struct TcplSession , tcplsession_rbnode )
TRAVEL_RBTREENODE( TravelTcplSessionTreeNode , struct TcplStatEnv , tcpl_sessions_rbtree , struct TcplSession , tcplsession_rbnode )
DESTROY_RBTREE( DestroyTcplSessionTree , struct TcplStatEnv , tcpl_sessions_rbtree , struct TcplSession , tcplsession_rbnode , FreeTcplSessionTreeNodeEntry )

