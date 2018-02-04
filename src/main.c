/*
 * tcplstat - TCP packets monitor and statistical tool
 * author	: calvin
 * email	: calvinwilliams@163.com
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#include "tcplstat_in.h"

char    __TCPLSTAT_VERSION_0_0_1[] = "0.0.1" ;
char    *__TCPLSTAT_VERSION = __TCPLSTAT_VERSION_0_0_1 ;

static void version()
{
	printf( "tcplstat v%s build %s %s\n" , __TCPLSTAT_VERSION , __DATE__ , __TIME__ );
	return;
}

static void usage()
{
	printf( "USAGE : tcplstat -v\n" );
	printf( "                 [ -i (network_interface) ] [ -f (filter_string) ] [ -v | -vv | -vvv ]\n" );
	printf( "NOTICE : See pcap-filter(7) for the syntax of filter\n" );
	return;
}

int main( int argc , char *argv[] )
{
	struct TcplStatEnv	env , *p_env = & env ;
	int			i ;
	
	bpf_u_int32		net ;
	bpf_u_int32		net_mask ;
	struct bpf_program	pcap_filter ;
	
	int			nret = 0 ;
	
	setbuf( stdout , NULL );
	
	if( argc == 1 )
	{
		usage();
		exit(0);
	}
	
	memset( & env , 0x00 , sizeof(struct TcplStatEnv) );
	
	for( i = 1 ; i < argc ; i++ )
	{
		if( STRCMP( argv[i] , == , "-v" ) )
		{
			version();
			exit(0);
		}
		else if( STRCMP( argv[i] , == , "-i" ) && i + 1 < argc )
		{
			p_env->cmd_line_para.network_interface = argv[i+1] ;
			i++;
		}
		else if( STRCMP( argv[i] , == , "-l" ) )
		{
			pcap_if_t	*network_interface_list = NULL ;
			pcap_if_t	*network_interface = NULL ;
			
			nret = pcap_findalldevs( & network_interface_list , p_env->pcap_errbuf ) ;
			if( nret == -1 )
			{
				printf( "*** ERROR : pcap_findalldevs failed , errbuf[%s]\n" , p_env->pcap_errbuf );
				return 1;
			}
			
			network_interface = network_interface_list ;
			while( network_interface )
			{
				printf( "%s %s\n" , network_interface->name , network_interface->description );
				
				network_interface = network_interface->next ;
			}
			
			pcap_freealldevs( network_interface_list );
			
			exit(0);
		}
		else if( STRCMP( argv[i] , == , "-f" ) && i + 1 < argc )
		{
			p_env->cmd_line_para.filter_string = argv[i+1] ;
			i++;
		}
		else if( STRCMP( argv[i] , == , "-v" ) )
		{
			p_env->cmd_line_para.output_level = OUTPUT_LEVEL_1 ;
		}
		else if( STRCMP( argv[i] , == , "-vv" ) )
		{
			p_env->cmd_line_para.output_level = OUTPUT_LEVEL_2 ;
		}
		else if( STRCMP( argv[i] , == , "-vvv" ) )
		{
			p_env->cmd_line_para.output_level = OUTPUT_LEVEL_3 ;
		}
		else
		{
			printf( "***ERROR : invalid command parameter '%s'\n" , argv[i] );
			usage();
			exit(1);
		}
	}
	
	if( p_env->cmd_line_para.network_interface == NULL )
	{
		p_env->cmd_line_para.network_interface = "any" ;
	}
	else
	{
		pcap_if_t	*network_interface_list = NULL ;
		pcap_if_t	*network_interface = NULL ;
		
		nret = pcap_findalldevs( & network_interface_list , p_env->pcap_errbuf ) ;
		if( nret == -1 )
		{
			printf( "*** ERROR : pcap_findalldevs failed , errbuf[%s]\n" , p_env->pcap_errbuf );
			return 1;
		}
		
		network_interface = network_interface_list ;
		while( network_interface )
		{
			if( STRCMP( network_interface->name , == , p_env->cmd_line_para.network_interface ) )
				break;
			
			network_interface = network_interface->next ;
		}
		
		pcap_freealldevs( network_interface_list );
		
		if( network_interface == NULL )
		{
			printf( "*** ERROR : network interface [%s] not found\n" , p_env->cmd_line_para.network_interface );
			return 1;
		}
	}
	
	if( p_env->cmd_line_para.filter_string == NULL )
		p_env->cmd_line_para.filter_string = "" ;
	
	nret = pcap_lookupnet( p_env->cmd_line_para.network_interface , & net , & net_mask , p_env->pcap_errbuf ) ;
	if( nret == -1 )
	{
		printf( "*** ERROR : pcap_lookupnet failed , errbuf[%s]\n" , p_env->pcap_errbuf );
		return 1;
	}
	
	p_env->pcap = pcap_open_live( p_env->cmd_line_para.network_interface , 65535 , 1 , 2000 , p_env->pcap_errbuf ) ;
	if( p_env->pcap == NULL )
	{
		printf( "*** ERROR : pcap_open_live failed , errbuf[%s]\n" , p_env->pcap_errbuf );
		return 1;
	}
	
	memset( & pcap_filter , 0x00 , sizeof(struct bpf_program) );
	nret = pcap_compile( p_env->pcap , & pcap_filter , p_env->cmd_line_para.filter_string , 0 , net_mask ) ;
	if( nret == -1 )
	{
		printf( "*** ERROR : pcap_compile failed , errbuf[%s]\n" , p_env->pcap_errbuf );
		pcap_close( p_env->pcap );
		return 1;
	}
	
	nret = pcap_setfilter( p_env->pcap , & pcap_filter ) ;
	if( nret == -1 )
	{
		printf( "*** ERROR : pcap_setfilter failed , errbuf[%s]\n" , p_env->pcap_errbuf );
		pcap_close( p_env->pcap );
		return 1;
	}
	
	pcap_loop( p_env->pcap , -1 , PcapCallback , (u_char *)p_env );
	
	pcap_close( p_env->pcap );
	
	return 0;
}

