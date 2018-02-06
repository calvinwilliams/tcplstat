/*
 * tcplstat - TCP packets monitor and statistical tool
 * author	: calvin
 * email	: calvinwilliams@163.com
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#include "tcplstat_in.h"

char *memndup( const char *s, size_t n )
{
	char	*p = NULL ;
	
	p = (char*)malloc( n ) ;
	if( p == NULL )
		return NULL;
	memcpy( p , s , n );
	
	return p;
}

char *memistr2_region( char *p_curr , char *find , char *end , unsigned char binary_mode )
{
	char	*p_match = NULL ;
	char	*bak = NULL ;
	
	while( p_curr <= end )
	{
		if( binary_mode == 0 && ! isprint(*p_curr) )
			break;
		
		if( p_match == NULL )
		{
			if( toupper(*p_curr) == toupper(*find) )
			{
				p_match = find + 1 ;
				bak = p_curr ;
			}
		}
		else
		{
			if( toupper(*p_curr) == toupper(*p_match) )
			{
				p_match++;
				if( (*p_match) == '\0' )
					return bak;
			}
			else
			{
				p_match = NULL ;
				p_curr = bak ;
			}
		}
		
		p_curr++;
	}
	
	return NULL;
}

int LengthUtilEndOfText( char *p_curr , char *end )
{
	char	*p = NULL ;
	
	for( p = p_curr ; p <= end ; p++ )
	{
		if( ! isprint(*p) )
		{
			p--;
			break;
		}
	}
	
	return p-p_curr+1;
}

int DumpBuffer( char *indentation , char *pathfilename , int buf_len , void *buf )
{
	FILE		*fp = NULL ;
	int		lines_offset , bytes_offset ;
	
	if( indentation == NULL )
		indentation = "" ;
	
	if( STRCMP( pathfilename , == , "#stdin" ) )
	{
		fp = stdout ;
	}
	else if( STRCMP( pathfilename , == , "#stdout" ) )
	{
		fp = stdout ;
	}
	else if( STRCMP( pathfilename , == , "#stderr" ) )
	{
		fp = stderr ;
	}
	else
	{
		fp = fopen( pathfilename , "a" ) ;
		if( fp == NULL )
		{
			return -1;
		}
	}
	
	/* 写日志 */
	fprintf( fp , "%s             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF\n" , indentation );
	
	lines_offset = 0 ;
	bytes_offset = 0 ;
	
	while(1)
	{
		fprintf( fp , "%s0x%08X   " , indentation , (unsigned int)(lines_offset*16) );
		
		for( bytes_offset = 0 ; bytes_offset < 16 ; bytes_offset++ )
		{
			if( lines_offset*16 + bytes_offset < buf_len )
				fprintf( fp , "%02X " , *( (unsigned char *)buf + lines_offset * 16 + bytes_offset ) );
			else
				fprintf( fp , "   " );
		}
		
		fprintf( fp , "  " );
		
		for( bytes_offset = 0 ; bytes_offset < 16 ; bytes_offset++ )
		{
			if( lines_offset*16 + bytes_offset < buf_len )
			{
				unsigned char		ch = *( (unsigned char *)buf + lines_offset * 16 + bytes_offset ) ;
				
				if( 32 <= ch && ch <= 125 )
					fprintf( fp , "%c" , ch );
				else
					fputc( '.' , fp );
			}
			else
			{
				fprintf( fp , " " );
			}
		}
		
		fputc( '\n' , fp );
		
		if( ! ( lines_offset*16 + bytes_offset < buf_len ) )
			break;
		
		lines_offset++;
		
		if( ! ( lines_offset*16 < buf_len ) )
			break;
	}
	
	/* 关闭文件 */
	if( STRCMP( pathfilename , == , "#stdin" ) )
		;
	else if( STRCMP( pathfilename , == , "#stdout" ) )
		;
	else if( STRCMP( pathfilename , == , "#stderr" ) )
		;
	else
		fclose( fp );
	
	return 0;
}

