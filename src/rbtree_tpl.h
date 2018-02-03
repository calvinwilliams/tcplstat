/*
 * rbtree_tpl
 * author	: calvin
 * email	: calvinwilliams@163.com
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#include "rbtree.h"

#define LINK_RBTREENODE_STRING( _this_func_ , _struct_ENV_ , _p_env_member_rbtree_ , _struct_UNIT_ , _p_unit_member_rbnode_ , _p_unit_member_str_ ) \
	int _this_func_( _struct_ENV_ *_p_env , _struct_UNIT_ *_p_unit ) \
	{ \
		struct rb_node		**_pp_add_node = NULL ;	\
		struct rb_node		*_p_parent = NULL ; \
		_struct_UNIT_		*_p = NULL ; \
		int			_result ; \
		\
		_pp_add_node = & (_p_env->_p_env_member_rbtree_.rb_node) ; \
		while( *_pp_add_node ) \
		{ \
			_p = container_of( *_pp_add_node , _struct_UNIT_ , _p_unit_member_rbnode_ ) ; \
			_p_parent = (*_pp_add_node) ; \
			\
			_result = strcmp( _p_unit->_p_unit_member_str_ , _p->_p_unit_member_str_ ) ; \
			if( _result < 0 ) \
				_pp_add_node = & ((*_pp_add_node)->rb_left) ; \
			else if( _result > 0 ) \
				_pp_add_node = & ((*_pp_add_node)->rb_right) ; \
			else \
				return -1; \
		} \
		\
		rb_link_node( & (_p_unit->_p_unit_member_rbnode_) , _p_parent , _pp_add_node ); \
		rb_insert_color( & (_p_unit->_p_unit_member_rbnode_) , & (_p_env->_p_env_member_rbtree_) ); \
		\
		return 0; \
	} \

#define QUERY_RBTREENODE_STRING( _this_func_ , _struct_ENV_ , _p_env_member_rbtree_ , _struct_UNIT_ , _p_unit_member_rbnode_ , _p_unit_member_str_ ) \
	_struct_UNIT_ *_this_func_( _struct_ENV_ *_p_env , _struct_UNIT_ *_p_unit ) \
	{ \
		struct rb_node		*_query_node = _p_env->_p_env_member_rbtree_.rb_node ; \
		_struct_UNIT_		*_p = NULL ; \
		int			_result ; \
		\
		while( _query_node ) \
		{ \
			_p = container_of( _query_node , _struct_UNIT_ , _p_unit_member_rbnode_ ) ; \
			\
			_result = strcmp( _p_unit->_p_unit_member_str_ , _p->_p_unit_member_str_ ) ; \
			if( _result < 0 ) \
				_query_node = _query_node->rb_left ; \
			else if( _result > 0 ) \
				_query_node = _query_node->rb_right ; \
			else \
				return _p; \
		} \
		\
		return NULL; \
	} \

#define LINK_RBTREENODE_INT( _this_func_ , _struct_ENV_ , _p_env_member_rbtree_ , _struct_UNIT_ , _p_unit_member_rbnode_ , _p_unit_member_str_ ) \
	int _this_func_( _struct_ENV_ *_p_env , _struct_UNIT_ *_p_unit ) \
	{ \
		struct rb_node		**_pp_add_node = NULL ;	\
		struct rb_node		*_p_parent = NULL ; \
		_struct_UNIT_		*_p = NULL ; \
		\
		_pp_add_node = & (_p_env->_p_env_member_rbtree_.rb_node) ; \
		while( *_pp_add_node ) \
		{ \
			_p = container_of( *_pp_add_node , _struct_UNIT_ , _p_unit_member_rbnode_ ) ; \
			_p_parent = (*_pp_add_node) ; \
			\
			if( _p_unit->_p_unit_member_str_ < _p->_p_unit_member_str_ ) \
				_pp_add_node = & ((*_pp_add_node)->rb_left) ; \
			else if( _p_unit->_p_unit_member_str_ > _p->_p_unit_member_str_ ) \
				_pp_add_node = & ((*_pp_add_node)->rb_right) ; \
			else \
				return -1; \
		} \
		\
		rb_link_node( & (_p_unit->_p_unit_member_rbnode_) , _p_parent , _pp_add_node ); \
		rb_insert_color( & (_p_unit->_p_unit_member_rbnode_) , & (_p_env->_p_env_member_rbtree_) ); \
		\
		return 0; \
	} \

#define QUERY_RBTREENODE_INT( _this_func_ , _struct_ENV_ , _p_env_member_rbtree_ , _struct_UNIT_ , _p_unit_member_rbnode_ , _p_unit_member_str_ ) \
	_struct_UNIT_ *_this_func_( _struct_ENV_ *_p_env , _struct_UNIT_ *_p_unit ) \
	{ \
		struct rb_node		*_query_node = _p_env->_p_env_member_rbtree_.rb_node ; \
		_struct_UNIT_		*_p = NULL ; \
		\
		while( _query_node ) \
		{ \
			_p = container_of( _query_node , _struct_UNIT_ , _p_unit_member_rbnode_ ) ; \
			\
			if( _p_unit->_p_unit_member_str_ < _p->_p_unit_member_str_ ) \
				_query_node = _query_node->rb_left ; \
			else if( _p_unit->_p_unit_member_str_ > _p->_p_unit_member_str_ ) \
				_query_node = _query_node->rb_right ; \
			else \
				return _p; \
		} \
		\
		return NULL; \
	} \

#define LINK_RBTREENODE_INT_ALLOWDUPLICATE( _this_func_ , _struct_ENV_ , _p_env_member_rbtree_ , _struct_UNIT_ , _p_unit_member_rbnode_ , _p_unit_member_str_ ) \
	int _this_func_( _struct_ENV_ *_p_env , _struct_UNIT_ *_p_unit ) \
	{ \
		struct rb_node		**_pp_add_node = NULL ;	\
		struct rb_node		*_p_parent = NULL ; \
		_struct_UNIT_		*_p = NULL ; \
		\
		_pp_add_node = & (_p_env->_p_env_member_rbtree_.rb_node) ; \
		while( *_pp_add_node ) \
		{ \
			_p = container_of( *_pp_add_node , _struct_UNIT_ , _p_unit_member_rbnode_ ) ; \
			_p_parent = (*_pp_add_node) ; \
			\
			if( _p_unit->_p_unit_member_str_ < _p->_p_unit_member_str_ ) \
				_pp_add_node = & ((*_pp_add_node)->rb_left) ; \
			else if( _p_unit->_p_unit_member_str_ > _p->_p_unit_member_str_ ) \
				_pp_add_node = & ((*_pp_add_node)->rb_right) ; \
			else \
				_pp_add_node = & ((*_pp_add_node)->rb_right) ; \
		} \
		\
		rb_link_node( & (_p_unit->_p_unit_member_rbnode_) , _p_parent , _pp_add_node ); \
		rb_insert_color( & (_p_unit->_p_unit_member_rbnode_) , & (_p_env->_p_env_member_rbtree_) ); \
		\
		return 0; \
	} \

typedef int funcCompareRbTreeNodeEntry( void *pv1 , void *pv2 );

#define LINK_RBTREENODE( _this_func_ , _struct_ENV_ , _p_env_member_rbtree_ , _struct_UNIT_ , _p_unit_member_rbnode_ , _cmp_func_ ) \
	int _this_func_( _struct_ENV_ *_p_env , _struct_UNIT_ *_p_unit ) \
	{ \
		struct rb_node			**_pp_add_node = NULL ;	\
		struct rb_node			*_p_parent = NULL ; \
		_struct_UNIT_			*_p = NULL ; \
		funcCompareRbTreeNodeEntry	*_pfuncCompareRbTreeNodeEntry = (funcCompareRbTreeNodeEntry *)_cmp_func_ ; \
		int				_result ; \
		\
		_pp_add_node = & (_p_env->_p_env_member_rbtree_.rb_node) ; \
		while( *_pp_add_node ) \
		{ \
			_p = container_of( *_pp_add_node , _struct_UNIT_ , _p_unit_member_rbnode_ ) ; \
			_p_parent = (*_pp_add_node) ; \
			\
			_result = _pfuncCompareRbTreeNodeEntry( (void*)_p_unit , (void*)_p ) ; \
			if( _result < 0 ) \
				_pp_add_node = & ((*_pp_add_node)->rb_left) ; \
			else if( _result > 0 ) \
				_pp_add_node = & ((*_pp_add_node)->rb_right) ; \
			else \
				return -1; \
		} \
		\
		rb_link_node( & (_p_unit->_p_unit_member_rbnode_) , _p_parent , _pp_add_node ); \
		rb_insert_color( & (_p_unit->_p_unit_member_rbnode_) , & (_p_env->_p_env_member_rbtree_) ); \
		\
		return 0; \
	} \

#define QUERY_RBTREENODE( _this_func_ , _struct_ENV_ , _p_env_member_rbtree_ , _struct_UNIT_ , _p_unit_member_rbnode_ , _cmp_func_ ) \
	_struct_UNIT_ *_this_func_( _struct_ENV_ *_p_env , _struct_UNIT_ *_p_unit ) \
	{ \
		struct rb_node			*_query_node = _p_env->_p_env_member_rbtree_.rb_node ; \
		_struct_UNIT_			*_p = NULL ; \
		funcCompareRbTreeNodeEntry	*_pfuncCompareRbTreeNodeEntry = (funcCompareRbTreeNodeEntry *)_cmp_func_ ; \
		int				_result ; \
		\
		while( _query_node ) \
		{ \
			_p = container_of( _query_node , _struct_UNIT_ , _p_unit_member_rbnode_ ) ; \
			\
			_result = _pfuncCompareRbTreeNodeEntry( (void*)_p_unit , (void*)_p ) ; \
			if( _result < 0 ) \
				_query_node = _query_node->rb_left ; \
			else if( _result > 0 ) \
				_query_node = _query_node->rb_right ; \
			else \
				return _p; \
		} \
		\
		return NULL; \
	} \

#define UNLINK_RBTREENODE( _this_func_ , _struct_ENV_ , _p_env_member_rbtree_ , _struct_UNIT_ , _p_unit_member_rbnode_ ) \
	void _this_func_( _struct_ENV_ *_p_env , _struct_UNIT_ *_p_unit ) \
	{ \
		rb_erase( & (_p_unit->_p_unit_member_rbnode_) , & (_p_env->_p_env_member_rbtree_) ); \
		return; \
	} \

#define UPDATE_RBTREENODE( _this_func_ , _remove_func_ , _add_func_ , _struct_ENV_ , _struct_UNIT_ ) \
	int _this_func_( _struct_ENV_ *_p_env , _struct_UNIT_ *_p_unit ) \
	{ \
		_remove_func_( _p_env , _p_unit ); \
		return _add_func_( _p_env , _p_unit ); \
	} \

#define TRAVEL_RBTREENODE( _this_func_ , _struct_ENV_ , _p_env_member_rbtree_ , _struct_UNIT_ , _p_unit_member_rbnode_ ) \
	_struct_UNIT_ *_this_func_( _struct_ENV_ *_p_env , _struct_UNIT_ *_p_unit ) \
	{ \
		struct rb_node		*_p_travel = NULL ; \
		\
		if( _p_unit == NULL ) \
		{ \
			_p_travel = rb_first( & (_p_env->_p_env_member_rbtree_) ) ; \
			if (_p_travel == NULL) \
				return NULL; \
		} \
		else \
		{ \
			_p_travel = rb_next( & (_p_unit->_p_unit_member_rbnode_) ) ; \
			if (_p_travel == NULL) \
				return NULL; \
		} \
		\
		return rb_entry( _p_travel , _struct_UNIT_ , _p_unit_member_rbnode_ ); \
	} \

typedef void funcFreeRbTreeNodeEntry( void *pv );

#define FREE_RBTREENODEENTRY_DIRECTLY		((void*)1)

#define DESTROY_RBTREE( _this_func_ , _struct_ENV_ , _p_env_member_rbtree_ , _struct_UNIT_ , _p_unit_member_rbnode_ , _free_func_ ) \
	void _this_func_( _struct_ENV_ *_p_env ) \
	{ \
		struct rb_node		*_p_free = NULL ; \
		_struct_UNIT_		*_p_unit = NULL ; \
		funcFreeRbTreeNodeEntry	*_pfuncFreeRbTreeNodeEntry = (funcFreeRbTreeNodeEntry *)_free_func_ ; \
		\
		while( ( _p_free = rb_first( & (_p_env->_p_env_member_rbtree_) ) ) ) \
		{ \
			rb_erase( _p_free , & (_p_env->_p_env_member_rbtree_) ); \
			\
			if( _pfuncFreeRbTreeNodeEntry == FREE_RBTREENODEENTRY_DIRECTLY ) \
			{ \
				_p_unit = rb_entry( _p_free , _struct_UNIT_ , _p_unit_member_rbnode_ ) ; \
				free( _p_unit ); \
			} \
			else if( _pfuncFreeRbTreeNodeEntry ) \
			{ \
				_p_unit = rb_entry( _p_free , _struct_UNIT_ , _p_unit_member_rbnode_ ) ; \
				_pfuncFreeRbTreeNodeEntry( _p_unit ); \
			} \
		} \
	} \

