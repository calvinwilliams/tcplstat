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

LINK_RBTREENODE( LinkTcplSessionTreeNode , struct TcplStatEnv , tcplsessions_rbtree , struct TcplSession , tcplsession_rbnode , CompareTcplSessionTreeNodeEntry )
QUERY_RBTREENODE( QueryTcplSessionTreeNode , struct TcplStatEnv , tcplsessions_rbtree , struct TcplSession , tcplsession_rbnode , CompareTcplSessionTreeNodeEntry )
UNLINK_RBTREENODE( UnlinkTcplSessionTreeNode , struct TcplStatEnv , tcplsessions_rbtree , struct TcplSession , tcplsession_rbnode )
TRAVEL_RBTREENODE( TravelTcplSessionTreeNode , struct TcplStatEnv , tcplsessions_rbtree , struct TcplSession , tcplsession_rbnode )
DESTROY_RBTREE( DestroyTcplSessionTree , struct TcplStatEnv , tcplsessions_rbtree , struct TcplSession , tcplsession_rbnode , FREE_RBTREENODEENTRY_DIRECTLY )

