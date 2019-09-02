#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <math.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <pwd.h>
#include <dirent.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/timeb.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include "libc.h"

#define	LIBC_TIMEOUT	5

static void libc_signal( int sig_no ){ }
static int libc_opensocket( const char *host,const char *port );
static void libc_closesocket( int handle );
static int libc_writesocket( int handle,SSL *ssl,const char *data,size_t size );
static int libc_printsocket( int handle,SSL *ssl,const char *fmt, ... );
static int libc_readsocket( int handle,SSL *ssl,char **data,size_t *size );

extern unsigned long libc_longtime( void )
{
	struct timeval tv;
	gettimeofday( &tv,NULL );
	return (unsigned long)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

/* 日時データ -> 文字列変換 */
extern char* libc_stringtime( const struct tm *src,char *dst,size_t len )
{
	if( !src ) return NULL;
	if( len <= 0 ) len = 14; /* DEFAULT */
	if( !dst && (dst = (char*)malloc( len + 1 )) == NULL ) return NULL;

	if( len == 32 || len == 34 ){ /* for cookie or rss-pubDate */
		const char *mons[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
		const char *week[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
		struct tm gmt; memcpy( &gmt,src,sizeof(gmt) );
		if( len == 32 ){
			gmt.tm_hour -= 9; mktime( &gmt );
			sprintf( dst,"%s, %d-%s-%04d %02d:%02d:%02d GMT",week[gmt.tm_wday],
				gmt.tm_mday,mons[gmt.tm_mon],gmt.tm_year + 1900,gmt.tm_hour,gmt.tm_min,gmt.tm_sec );
		}
		else{
			sprintf( dst,"%s, %02d %s %04d %02d:%02d:%02d +0900",week[gmt.tm_wday],
				gmt.tm_mday,mons[gmt.tm_mon],gmt.tm_year + 1900,gmt.tm_hour,gmt.tm_min,gmt.tm_sec );
		}
	}
	else if( len == 10 ) sprintf( dst,"%04d-%02d-%02d",src->tm_year + 1900,src->tm_mon + 1,src->tm_mday );			
	else if( len == 14 ) sprintf( dst,"%04d%02d%02d%02d%02d%02d",src->tm_year + 1900,src->tm_mon + 1,
		src->tm_mday,src->tm_hour,src->tm_min,src->tm_sec );
	else sprintf( dst,"%04d-%02d-%02d %02d:%02d:%02d",src->tm_year + 1900,src->tm_mon + 1,
		src->tm_mday,src->tm_hour,src->tm_min,src->tm_sec ); /* len == 19 */
	return dst;
}

extern char* libc_readfile( const char *path,size_t *size )
{
	FILE *fp; char *ptr = NULL; size_t len = 0; int ret = 0;

	if( size ) *size = 0;
	if( strnull(path) ) return NULL;
	if( (fp = fopen( path,"rb" )) != NULL ){
		fseek( fp,0L,SEEK_END );
		len = (size_t)ftell( fp );
		if( (ptr = (char*)malloc( len + 1 )) != NULL ){
			rewind( fp );
			ret = fread( ptr,len,1,fp ); /* 一気読み */
			ptr[len] = '\0';
		}
		fclose( fp );
	}
	if( ret <= 0 ){
		if( ptr ) free( ptr );
		return NULL;
	}
	if( size ) *size = len;
	return ptr;
}

extern int libc_writefile( const char *path,const char *mode,const char *data,size_t size )
{
	int ret = 0; FILE *fp;

	if( !path || !mode || !data || size <= 0 ) return ret;

	if( (fp = libc_openfile( path,mode )) != NULL ){
		if( fwrite( data,size,1,fp ) > 0 ) ret = 1; /* 一気書き */
		libc_closefile( fp );
	}
	
	return ret; /* 0:NG 1:OK */
}

extern int libc_logfile( const char *path,const char *fmt, ... )
{
	int ret,msec; va_list va; char *ptr; FILE *fp;
	time_t now_t; struct tm now_d;
	struct timeval tv; struct timezone tz;

	if( !path ) return 0;

	va_start( va,fmt );
	ret = vasprintf( &ptr,fmt,va );
	va_end( va );

	if( ret < 0 || !ptr ) return 0;

	gettimeofday( &tv,&tz );
	now_t = tv.tv_sec; msec = (int)(tv.tv_usec / 1000);
	now_d = *(localtime( &now_t ));

	if( (fp = libc_openfile( path,"ab" )) != NULL ){
		fprintf( fp,"[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
			now_d.tm_year + 1900,now_d.tm_mon + 1,now_d.tm_mday,
			now_d.tm_hour,now_d.tm_min,now_d.tm_sec,msec );
		if( fwrite( ptr,ret,1,fp ) > 0 ) ret = 1; else ret = 0;
		libc_closefile( fp );
	}else ret = 0;

	free( ptr );

	return ret; /* 0:NG 1:OK */
}

extern FILE* libc_openfile( const char *path,const char *mode )
{
	FILE *ret = NULL; struct flock flk;

	if( !path || !mode ) return ret; /* NOP */

	if( (ret = fopen( path,mode )) != NULL ){
		flk.l_type	= F_WRLCK;
		flk.l_whence= SEEK_SET;
		flk.l_start	= 0;
		flk.l_len	= 0;
		if( fcntl( fileno( ret ),F_SETLKW,&flk ) != 0 ){
			fclose( ret ); ret = NULL;
		}
	}
	return ret;
}

extern int libc_closefile( FILE *stream )
{
	int ret = (-1); struct flock flk;

	if( !stream ) return ret;

	flk.l_type	= F_UNLCK;
	flk.l_whence= SEEK_SET;
	flk.l_start	= 0;
	flk.l_len	= 0;
	ret = fcntl( fileno( stream ),F_SETLKW,&flk );
	fclose( stream );
	
	return ret;
}

extern libc_array* libc_readconfigfile( const char *path )
{
	char *mem,*p1,*p2,*p3,*p4,*key,*val; libc_array *ret; int n; size_t len;

	if( (mem = libc_readfile( path,NULL )) == NULL ) return NULL;
	for( p1 = mem,n = 0; (p2 = strstr( p1,"=\"" )) != NULL; p1 = p2 + 2 ){ n++; }
	if( n <= 0 ) return NULL; /* NOP */
	if( (ret = (libc_array*)calloc( 1,sizeof(libc_array) )) == NULL ) return NULL;
	if( (ret->items = (libc_item*)malloc( sizeof(libc_item) * n )) == NULL ){
		free( ret ); return NULL; /* alloc error */
	}
	for( p1 = mem; (p2 = strstr( p1,"=\"" )) != NULL; p1 = p2 + 2 ){
		if( p1 == p2 || *(p2 + 2) == '\0' || *(p2 + 2) == '"' ) continue;
		for( p3 = p2 - 1; p3 != mem && *p3 != '\r' && *p3 != '\n'; p3-- ){ ; }
		if( p3 != mem ) p3++; if( *p3 == '#' ) continue;
		if( (p4 = strchr( p2 + 2,'"' )) == NULL ) p4 = strchr( p2 + 2,'\0' );
		len = (size_t)p2 - (size_t)p3;
		if( (key = (char*)malloc( len + 1 )) != NULL ){
			memcpy( key,p3,len ); key[len] = '\0';
			p2 += 2; len = (size_t)p4 - (size_t)p2;
			if( (val = (char*)malloc( len + 1 )) != NULL ){
				memcpy( val,p2,len ); val[len] = '\0';
				ret->items[ret->count].name = key;
				ret->items[ret->count].data = val;
				ret->items[ret->count].size = len;
				ret->items[ret->count].file = NULL;
				ret->count++;
			}else free( key );
		}
	}free( mem );
	return ret; /* allocated array */
}

extern libc_array* libc_readcgiparams( void )
{
	char *ptr,*mem = NULL; size_t len = 0; libc_array *ret = NULL;

	if( (ptr = getenv( "QUERY_STRING" )) != NULL && (len = strlen( ptr )) > 0 ){
		mem = strdup( ptr );
	}else if( (ptr = getenv( "CONTENT_LENGTH" )) != NULL && (len = atoi( ptr )) > 0 ){
		if( (mem = (char*)malloc( len + 1 )) != NULL ){
			fread( mem,len,1,stdin ); mem[len] = '\0';
		}
	}
	if( !mem ) return NULL; /* NOT CGI */

	if( strstr( mem,"Content-Disposition: form-data; name=\"" ) != NULL ){
		ret = libc_readmultipart( mem,len );
	}
	else{
		ret = libc_readsinglepart( mem,len,'&' );
	}
	return ret;
}

extern libc_array* libc_readcookieparams( void )
{
	char *ptr,*mem = NULL; size_t len = 0; libc_array *ret = NULL;

	if( (ptr = getenv( "HTTP_COOKIE" )) != NULL && (len = strlen( ptr )) > 0 ){
		mem = strdup( ptr );
	}
	if( !mem ) return NULL; /* NOT COOKIE */

	ret = libc_readsinglepart( mem,len,';' );

	return ret;
}

extern char* libc_searchdata( const libc_array *array,const char *name,int *index )
{
	int i; char *ret = NULL;

	if( index ) *index = 0;
	if( !array || !name ) return ret;
	for( i = 0; i < array->count; i++ ){
		if( strcmp( array->items[i].name,name ) == 0 ){
			ret = array->items[i].data;
			if( index ) *index = i;
			break;
		}
	}
	return ret;
}

extern void libc_freearray( libc_array *array )
{
	int i;

	if( !array ) return;

	for( i = 0; i < array->count; i++ ){
		if( array->items[i].name ) free( array->items[i].name );
		if( array->items[i].data ) free( array->items[i].data );
		if( array->items[i].file ) free( array->items[i].file );
	}
	free( array->items );
	free( array );
}

extern libc_array* libc_readsinglepart( char *mem,size_t len,char sep )
{
	char *fr,*to,*bg,*en,*key,*val; size_t k_len,v_len; int ok;
	libc_array *ret = NULL;

	/* malloc１発確保にしたいため、あらかじめ要素数を計測 */
	for( fr = mem,ok = 0; (to = strchr( fr,'=' )) != NULL; fr = to + 1 ){
		if( fr != to && *(to + 1) != '\0' ) ok++;
	}if( ok <= 0 ) return NULL; /* NOP */
	if( (ret = (libc_array*)calloc( 1,sizeof(libc_array) )) == NULL ) return NULL;
	if( (ret->items = (libc_item*)malloc( sizeof(libc_item) * ok )) == NULL ){
		free( ret ); return NULL; /* alloc error */
	}
	for( fr = mem; (to = strchr( fr,'=' )) != NULL; fr = to + 1 ){
		key = NULL; val = NULL; ok = 0;
		k_len = (size_t)to - (size_t)fr; bg = to + 1;
		if( (en = strchr( bg,sep )) != NULL ){ *(to = en) = '\0'; }
		else{ en = mem + len; to = en - 1; }
		if( k_len > 0 && (key = (char*)malloc( k_len + 1 )) != NULL ){
			memcpy( key,fr,k_len ); key[k_len] = '\0';
			if( !libc_searchdata( ret,key,NULL ) &&
				(val = libc_decodeurl( bg,NULL )) != NULL ){
				v_len = strlen( val );
				ret->items[ret->count].name = key;
				ret->items[ret->count].data = val;
				ret->items[ret->count].size = v_len;
				ret->items[ret->count].file = NULL;
				ret->count++; ok = 1;
			}
		}
		if( !ok ){ if( key ) free( key ); if( val ) free( val ); } /* read error */
		if( *(to + 1) == ' ' ) to++;
	}
	return ret; /* allocated array */
}

extern libc_array* libc_readmultipart( char *mem,size_t len )
{
	char *fr,*to,*bg,*en,*ptr; int i,ok; char sep[512]; size_t s_len;
	char *key; size_t k_len; char *fil; size_t f_len; char *val; size_t v_len;
	const char *con = "Content-Disposition: form-data; name=\"";
	libc_array *ret = NULL; size_t c_len = strlen( con );
	
	/* 区切り文字列の取得 ＆ 作成 */
	if( (ptr = strstr( mem,"\r\n" )) == NULL ||
		(s_len = (size_t)ptr - (size_t)mem) <= 0 ||
		s_len > sizeof(sep) - 3 ) return 0; /* BAD FORMAT */
	memcpy( sep + 2,mem,s_len ); sep[0] = '\r'; sep[1] = '\n';
	s_len += 2; sep[s_len] = '\0';

	/* 要素数の判定 */
	for( fr = mem,f_len = len,ok = 0; (to = (char*)memmem( fr,f_len,sep,s_len )) != NULL; ){
		fr = to + s_len; f_len = len - ((size_t)fr - (size_t)mem); ok++;
	}if( ok <= 0 ) return NULL; /* NOP */
	if( (ret = (libc_array*)calloc( 1,sizeof(libc_array) )) == NULL ) return NULL;
	if( (ret->items = (libc_item*)malloc( sizeof(libc_item) * ok )) == NULL ){
		free( ret ); return NULL; /* alloc error */
	}
	/* マルチパートデータ取得ループ */
	for( fr = mem; (to = strstr( fr,con )) != NULL; ){
		to += c_len; fr = to; key = NULL; fil = NULL; val = NULL;
		if( (ptr = strchr( to,'"' )) == NULL ||
			(k_len = (size_t)ptr - (size_t)to) <= 0 ||
			(key = (char*)malloc( k_len + 1 )) == NULL ) continue;
		memcpy( key,to,k_len ); key[k_len] = '\0';
		if( libc_searchdata( ret,key,NULL ) ){ free( key ); continue; } /* NOT OVERWRITE */
		ptr++;
		if( strncmp( ptr,"; filename=\"",12 ) == 0 ){
			ptr += 12; 
			if( (to = strchr( ptr,'"' )) == NULL ||
			(f_len = (size_t)to - (size_t)ptr) <= 0 ||
			(fil = (char*)malloc( f_len + 1 )) == NULL ){ free( key ); continue; }
			memcpy( fil,ptr,f_len ); fil[f_len] = '\0'; ptr = to + 1;
			for( i = f_len,ok = 1; i >= 0; i-- ){ /* ファイル名のみ抽出 */
				if( fil[i] == '\\' ){
					if( (to = (char*)malloc( f_len - i )) != NULL ){
						strcpy( to,&fil[i + 1] ); free( fil ); fil = to; f_len -= i;
					}else ok = 0; break;
				}
			}if( !ok ){ free( key ); if( fil ) free( fil ); continue; } 
		}
		if( (bg = strstr( ptr,"\r\n\r\n" )) == NULL ){
			free( key ); if( fil ) free( fil ); continue;
		}bg += 4;
		if( (en = (char*)memmem( bg,len - ((size_t)bg - (size_t)mem),sep,s_len )) == NULL ||
			(v_len = (size_t)en - (size_t)bg) <= 0 || (val = (char*)malloc( v_len + 1 )) == NULL ){
			free( key ); if( fil ) free( fil ); continue;
		}memcpy( val,bg,v_len ); val[v_len] = '\0'; fr = en + 1;
		ret->items[ret->count].name = key;
		ret->items[ret->count].data = val;
		ret->items[ret->count].size = v_len;
		ret->items[ret->count].file = fil;
		ret->count++;
	}
	return ret; /* allocated array */
}

extern libc_array* libc_readjsonpart( char *mem,size_t len )
{
	char *p1,*p2 = NULL,*p3 = NULL,*key = NULL,*val = NULL,c;
	libc_array *ret = NULL; int level = 0,valok = 0;
	
	if( !mem || len <= 0 ) return NULL;

	/* とりあえず最高要素数は500として、:の数で確保数を決める */
	for( p1 = mem,valok = 0; (p2 = strchr( p1,':' )) != NULL; p1 = p2 + 1 ){
		valok++; if( valok >= 500 ) break;
	}if( valok <= 0 ) return NULL; /* NOP */
	if( (ret = (libc_array*)calloc( 1,sizeof(libc_array) )) == NULL ) return NULL;
	if( (ret->items = (libc_item*)malloc( sizeof(libc_item) * valok )) == NULL ){
		free( ret ); return NULL; /* alloc error */
	}valok = 0;
	for( p1 = mem; *p1 != '\0'; p1++,valok = 0 ){
		if( level == 0 ){ /* キーの始まり待ち */
			if( *p1 == '\'' || *p1 == '"' ){
				p2 = p1; level = 1;
			}
		}
		else if( level == 1 ){ /* キーが始まり終わり待ち */
			if( *p1 == *p2 ){
				p3 = p1; p2++;
				if( p3 > p2 ){
					c = *p3; *p3 = '\0'; if( key ) free( key );
					key = strdup( p2 ); *p3 = c; level = 2;
				}
				else{
					level = 0; /* キー囲いがカラ */
				}
			}
		}
		else if( level == 2 ){ /* キーが終わり値の始まり待ち */
			if( *p1 == ':' || *p1 == '\t' || *p1 == ' ' || *p1 == '\r' || *p1 == '\n' ) continue;
			if( *p1 == '\'' || *p1 == '"' ){
				p2 = p1; level = 3; /* 文字列値の始まり */
			}
			else if( *p1 == '[' || *p1 == ']' || *p1 == '{' || *p1 == '}' || *p1 == ',' ){
				level = 0; /* キーの始まり待ちに戻る */
			}
			else{ /* 数値or真偽値の始まり */
				p2 = p1; level = 4;
			}
		}
		else if( level == 3 ){ /* 文字列値が始まり終わり待ち */
			if( *p1 != *p2 ) continue;
			p3 = p1; p2++;
			if( p3 > p2 ){
				c = *p3; *p3 = '\0'; if( val ) free( val );
				val = strdup( p2 ); *p3 = c; valok = 1;
			}
		}
		else if( level == 4 ){ /* 数値or真偽値の終わり待ち */
			if( *p1 >= '0' && *p1 <= '9' ) continue;
			if( *p1 == 't' || *p1 == 'r' || *p1 == 'u' || *p1 == 'e' ||
				*p1 == 'f' || *p1 == 'a' || *p1 == 'l' || *p1 == 's' ) continue;
			p3 = p1;
			if( p3 > p2 ){
				c = *p3; *p3 = '\0'; if( val ) free( val );
				val = strdup( p2 ); *p3 = c; valok = 1;
			}
		}
		if( valok ){
			ret->items[ret->count].name = key;
			ret->items[ret->count].data = val;
			ret->items[ret->count].size = strlen( val );
			ret->items[ret->count].file = NULL;
			ret->count++; key = NULL; val = NULL;
			level = 0; /* 戻る */
		}
	}
	if( key ) free( key ); if( val ) free( val );
	return ret; /* allocated array */
}

/* URLエンコード */
extern char* libc_encodeurl( const char *src,char *dst )
{
	int i,j;

	if( dst ) dst[0] = '\0';
	if( !src ) return NULL;
	if( !dst ) dst = (char*)malloc( strlen( src ) * 3 + 1 );
	if( !dst ) return NULL;

	for( i = 0,j = 0; src[i] != '\0'; i++ ){
		if( (src[i] >= '0' && src[i] <= '9') ||
			(src[i] >= 'A' && src[i] <= 'Z') ||
			(src[i] >= 'a' && src[i] <= 'z') ||
			src[i] == '_' || src[i] == '-' || src[i] == '.' ) dst[j++] = src[i];
		else if( src[i] == ' ' ) dst[j++] = '+';
		else j += sprintf( dst + j,"%%%02X",(unsigned char)(src[i]) );
	}dst[j] = '\0';

	return dst;
}

/* URLデコード */
extern char* libc_decodeurl( const char *src,char *dst )
{
	int i,j,num; char buf[8];

	if( dst ) dst[0] = '\0';
	if( !src ) return NULL;
	if( !dst ) dst = (char*)malloc( strlen( src ) + 1 );
	if( !dst ) return NULL;

	for( i = 0,j = 0; src[i] != '\0'; i++ ){
		if( src[i] == '%' ){
			if( src[i + 1] == '\0' || src[i + 2] == '\0' ) break; /* overflow */
			memcpy( buf,src + i,3 ); buf[3] = '\0';
			sscanf( buf,"%%%02X",&num );
			if( num > 255 ) break; /* overflow */
			dst[j++] = (char)num; i += 2;
		}else if( src[i] == '+' ) dst[j++] = ' ';
		else dst[j++] = src[i];
	}dst[j] = '\0'; return dst;
}

/* オリジナルXOR-HEXエンコード */
extern char* libc_encodexor( const char *src,char *dst )
{
	char buf[512]; int i,j; unsigned char mask = 0;

	if( dst ) dst[0] = '\0';
	if( strnull(src) ) return dst;

	mask = (unsigned char)(libc_longtime() % 256);
	if( mask == 0 ) mask = 0xFF;

	j = sprintf( buf,"%02x",mask );
	for( i = 0; src[i] != '\0'; i++ ){
		j += sprintf( buf + j,"%02x",((unsigned char)src[i]) ^ mask );
	}buf[j] = '\0';

	if( dst ) strcpy( dst,buf );
	else dst = strdup( buf );

	return dst;
}

/* オリジナルXOR-HEXデコード */
extern char* libc_decodexor( const char *src,char *dst )
{
	char buf[512],c,*srp; int i,j; unsigned char mask = 0;
	unsigned int v;

	if( dst ) dst[0] = '\0';
	if( strnull(src) ) return dst;

	for( i = 0,j = 0,srp = strdup( src ); srp[i] != '\0'; ){
		if( srp[i + 1] == '\0' ) break;
		c = srp[i + 2]; srp[i + 2] = '\0';
		if( i == 0 ){
			sscanf( &(srp[i]),"%02x",&v ); mask = (unsigned char)v;
		}
		else{
			sscanf( &(srp[i]),"%02x",&v ); buf[j] = (char)v;
			buf[j] ^= mask; j++;
		}
		srp[i + 2] = c; i += 2;
	}buf[j] = '\0'; free( srp );

	if( dst ) strcpy( dst,buf );
	else dst = strdup( buf );

	return dst;
}

/* HMAC-SHAエンコード 非可逆 evp = 1 or 256 or 512 */
extern unsigned char* libc_encodehmac( const char *src,const char *key,int evp,size_t *bin )
{
	char buf[EVP_MAX_MD_SIZE * 2 + 1]; int i,j;
	unsigned char bum[EVP_MAX_MD_SIZE]; unsigned int len = 0;
	unsigned char *ret = NULL;

	if( bin ) *bin = 0;

	if( !strnull(src) && !strnull(key) ){
		if( evp == 512 ){
			HMAC( EVP_sha512(),key,strlen( key ),(unsigned char*)src,strlen( src ),bum,&len );
		}
		else if( evp == 1 ){
			HMAC( EVP_sha1(),key,strlen( key ),(unsigned char*)src,strlen( src ),bum,&len );
		}
		else{
			HMAC( EVP_sha256(),key,strlen( key ),(unsigned char*)src,strlen( src ),bum,&len );
		}
		if( len > 0 ){
			if( bin ){
				if( (ret = (unsigned char*)malloc( len )) != NULL ){
					memcpy( ret,bum,len ); *bin = len;
				}
			}else{
				for( i = 0,j = 0; i < len; i++ ){
					j += sprintf( buf + j,"%02x",bum[i] );
				}buf[j] = '\0';
				ret = (unsigned char*)strdup( buf );
			}
		}
	}
	return ret;
}

static const char base64_table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '\0'
};

static const char base64_pad = '=';

static const short base64_reverse_table[256] = {
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
	-2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
	-2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2
};

/* Base64エンコード */
extern unsigned char* libc_encodebase64( const unsigned char *str,int length,int *ret_length,int url_safe )
{
	const unsigned char *current = str;
	unsigned char *p;
	unsigned char *result; int i,j,n;

	if ((length + 2) < 0 || ((length + 2) / 3) >= (1 << (sizeof(int) * 8 - 2))) {
		if (ret_length != NULL) {
			*ret_length = 0;
		}
		return NULL;
	}

	result = (unsigned char *)malloc(((length + 2) / 3) * 4 + 128);
	p = result;

	while (length > 2) { /* keep going until we have less than 24 bits */
		*p++ = base64_table[current[0] >> 2];
		*p++ = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
		*p++ = base64_table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
		*p++ = base64_table[current[2] & 0x3f];
		current += 3;
		length -= 3; /* we just handle 3 octets of data */
	}

	/* now deal with the tail end of things */
	if (length != 0) {
		*p++ = base64_table[current[0] >> 2];
		if (length > 1) {
			*p++ = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
			*p++ = base64_table[(current[1] & 0x0f) << 2];
			*p++ = base64_pad;
		} else {
			*p++ = base64_table[(current[0] & 0x03) << 4];
			*p++ = base64_pad;
			*p++ = base64_pad;
		}
	}
	if (ret_length != NULL) {
		*ret_length = (int)(p - result);
	}
	*p = '\0';
	if( url_safe ){
		for( i = 0,j = 0,n = strlen( (const char*)result ); i < n; i++ ){
			if( result[i] == '+' ) result[j] = '-';
			else if( result[i] == '/' ) result[j] = '_';
			else if( result[i] == '=' ) continue;
			j++;
		}result[j] = '\0';
	}
	return result;
}

/* Base64デコード */
extern unsigned char *libc_decodebase64( const unsigned char *str,int length,int *ret_length,int url_safe )
{
	unsigned char *current = (unsigned char*)str;
	int ch, i = 0, j = 0, k;
	/* this sucks for threaded environments */
	unsigned char *result,*p = NULL;
	int strict = 0;

	result = (unsigned char *)malloc(length + 128);
	if( url_safe ){
		for( i = 0; i < length; i++ ){
			if( current[i] == '-' ) result[i] = '+';
			else if( current[i] == '_' ) result[i] = '/';
			else result[i] = current[i];
		}
		j = 4 - (i % 4);
		if( j < 4 ){
			while( j-- ){
				result[i++] = '=';
			}
		}result[i] = '\0'; i = 0; j = 0;
		p = (unsigned char*)strdup( (const char*)result );
		current = p;
	}

	/* run through the whole string, converting as we go */
	while ((ch = *current++) != '\0' && length-- > 0) {
		if (ch == base64_pad) {
			if (*current != '=' && ((i % 4) == 1 || (strict && length > 0))) {
				if ((i % 4) != 1) {
					while (isspace(*(++current))) {
						continue;
					}
					if (*current == '\0') {
						continue;
					}
				}
				free(result); if( p ) free( p );
				return NULL;
			}
			continue;
		}
		ch = base64_reverse_table[ch];
		if ((!strict && ch < 0) || ch == -1) { /* a space or some other separator character, we simply skip over */
			continue;
		} else if (ch == -2) {
			free(result); if( p ) free( p );
			return NULL;
		}
		switch(i % 4) {
		case 0:
			result[j] = ch << 2;
			break;
		case 1:
			result[j++] |= ch >> 4;
			result[j] = (ch & 0x0f) << 4;
			break;
		case 2:
			result[j++] |= ch >>2;
			result[j] = (ch & 0x03) << 6;
			break;
		case 3:
			result[j++] |= ch;
			break;
		}
		i++;
	}
	k = j;
	/* mop things up if we ended on a boundary */
	if (ch == base64_pad) {
		switch(i % 4) {
		case 1:
			free(result); if( p ) free( p );
			return NULL;
		case 2:
			k++;
		case 3:
			result[k] = 0;
		}
	}
	if(ret_length) {
		*ret_length = j;
	}
	result[j] = '\0';
	if( p ) free( p );
	return result;
}

extern int libc_sendrecv( const char *host,const char *port,
	const char *senddata,size_t sendsize,char **recvdata,size_t *recvsize )
{
	SSL *ssl = NULL; SSL_CTX *ctx = NULL; unsigned short rand_ret;
	int ret = 0,handle = libc_opensocket( host,port );

	if( recvdata ) *recvdata = NULL; if( recvsize ) *recvsize = 0;
	if( handle < 0 ) return ret;

	if( atoi( port ) == 443 ){
		SSL_load_error_strings();
		SSL_library_init();
		if( (ctx = SSL_CTX_new( SSLv23_client_method() )) != NULL ){
			if( (ssl = SSL_new( ctx )) != NULL ){
				if( (ret = SSL_set_fd( ssl,handle )) != 0 ){
					RAND_poll();
					while( RAND_status() == 0 ){
						rand_ret = rand() % 65536;
						RAND_seed( &rand_ret,sizeof(rand_ret) );
					}
					if( (ret = SSL_connect( ssl )) == 1 ){
						libc_writesocket( (-1),ssl,senddata,sendsize );
						ret = libc_readsocket( (-1),ssl,recvdata,recvsize );
						SSL_shutdown( ssl );
					}
				}
				SSL_free( ssl );
			}
			SSL_CTX_free( ctx );
		}
	}else{
		libc_writesocket( handle,NULL,senddata,sendsize );
		ret = libc_readsocket( handle,NULL,recvdata,recvsize );
	}
	libc_closesocket( handle );
	return ret; /* RESULT CODE */
}

extern size_t libc_httpsplit( char *http,size_t hlen,char **head,char **body )
{
	char *ret_head = NULL,*ret_body = NULL; size_t ret_size = 0;
	char *p1,*p2,*p3,*p4; int chunk_size;

	if( head ) *head = NULL; if( body ) *body = NULL;
	if( !http || hlen <= 0 ) return 0;

	if( (p1 = strstr( http,"\r\n\r\n" )) == NULL ){ free( http ); return 0; } /* NO HEADER */
	*(p1 + 2) = '\0';
	ret_head = strdup( http );
	*(p1 + 2) = '\r';
	if( !ret_head ){ free( http ); return 0; }
	p3 = p1 + 4; /* SEEK TO BODY */

	if( (p1 = strcasestr( ret_head,"Content-Length: " )) != NULL &&
		(p2 = strchr( p1,'\r' )) != NULL ){
		p1 += 16; *p2 = '\0'; ret_size = atoi( p1 ); *p2 = '\r';
		if( (ret_body = (char*)malloc( ret_size + 1 )) != NULL ){
			memcpy( ret_body,p3,ret_size ); ret_body[ret_size] = '\0';
		}else ret_size = 0;
	}
	else if( strcasestr( ret_head,"Transfer-Encoding: chunked" ) ){
		if( (ret_body = (char*)malloc( hlen )) != NULL ){ /* 最大確保 */
		for( ; (p4 = strstr( p3,"\r\n" )) != NULL; p3 = p4 ){
			*p4 = '\0'; chunk_size = 0;
			if( strlen( p3 ) > 0 ) sscanf( p3,"%x",&chunk_size );
			*p4 = '\r'; p4 += 2;
			if( chunk_size > 0 ){
				memcpy( ret_body + ret_size,p4,chunk_size );
				ret_size += chunk_size; ret_body[ret_size] = '\0';
			}
			p4 += chunk_size;
		}}
	}
	if( head ) *head = ret_head; else free( ret_head );
	if( body ) *body = ret_body; else if( ret_body ) free( ret_body );
	free( http ); return ret_size;
}

extern int libc_getcookievalue( char *http,const char *name,char *value )
{
	char *p1,*p2,buf[256];

	if( strnull(http) || strnull(name) || !value ) return 0;

	sprintf( buf,"Set-Cookie: %s=",name );

	if( (p1 = strstr( http,buf )) != NULL && (p2 = strchr( p1,';' )) != NULL ){
		p1 += strlen( buf ); *p2 = '\0'; strcpy( value,p1 ); *p2 = ';';
		return 1; /* COMPLETE */
	}
	return 0;
}

extern int libc_gethiddenvalue( char *http,const char *name,char *value )
{
	char *p1,*p2,buf[256];

	if( strnull(http) || strnull(name) || !value ) return 0;

	sprintf( buf," name=\"%s\" value=\"",name );

	if( (p1 = strstr( http,buf )) != NULL && (p2 = strchr( p1 + strlen( buf ),'"' )) != NULL ){
		p1 += strlen( buf ); *p2 = '\0'; strcpy( value,p1 ); *p2 = '"';
		return 1; /* COMPLETE */
	}
	return 0;
}

static int libc_opensocket( const char *host,const char *port )
{
	int handle = (-1); struct sockaddr_in addr; struct hostent *servhost;
	void (*old_sigalrm)(int); unsigned int old_alarm;

	if( !host || !port ) return handle; /* NOP */

	servhost = gethostbyname( host );
	if( (handle = socket( AF_INET,SOCK_STREAM,0 )) >= 0 ){
		addr.sin_family = AF_INET;
		if( servhost ) memcpy( (char*)&addr.sin_addr,servhost->h_addr,servhost->h_length );
		else addr.sin_addr.s_addr = inet_addr( host );	
		addr.sin_port = htons( atoi( port ) );
		old_alarm = alarm( LIBC_TIMEOUT );
		old_sigalrm = signal( SIGALRM,libc_signal );
		if( connect( handle,(struct sockaddr *)&addr,sizeof(addr) ) != 0 ){
			close( handle ); handle = (-1);
		}
		(void)signal( SIGALRM,old_sigalrm );
		(void)alarm( old_alarm );
	}
	return handle;
}

static void libc_closesocket( int handle )
{
	if( handle >= 0 ) close( handle );
}

static int libc_writesocket( int handle,SSL *ssl,const char *data,size_t size )
{
	int ret = 0;

	if( (handle < 0 && !ssl) || !data || size <= 0 ) return 0; /* NOP */

	if( ssl ) ret = SSL_write( ssl,data,size );
	else ret = write( handle,data,size ); /*send( handle,data,size,0 );*/
	return ret;
}

static int libc_printsocket( int handle,SSL *ssl,const char *fmt, ... )
{
	int ret = 0; va_list va; char *ptr = NULL;

	if( handle < 0 && !ssl ) return ret; /* NOP */

	va_start( va,fmt );
	ret = vasprintf( &ptr,fmt,va );
	va_end( va );

	if( ret >= 0 && ptr ){
		ret = libc_writesocket( handle,ssl,ptr,ret );
		free( ptr );
	}else ret = 0;

	return ret;
}

static int libc_readsocket( int handle,SSL *ssl,char **data,size_t *size )
{
	char fnm[128],buf[1025],*ret_data; size_t ret_size,len; FILE *fp;

	if( data ) *data = NULL; if( size ) *size = 0;
	if( handle < 0 && !ssl ) return 0; /* NOP */
	/* テンポラリファイルのオープン */
	sprintf( fnm,"libc_readsocket.%d.tmp",getpid() );
	if( (fp = libc_openfile( fnm,"wb" )) == NULL ) return 0; /* FATAL */
	while( 1 ){
		if( ssl ) len = SSL_read( ssl,buf,sizeof(buf) - 1 );
		else len = read( handle,buf,sizeof(buf) - 1 ); /* recv( handle,buf,sizeof(buf) - 1,0 ); */
		if( len > 0 ) fwrite( buf,len,1,fp ); else break;
	}fclose( fp ); /* 書き込み完了 */
	ret_data = libc_readfile( fnm,&ret_size ); /* あらためて一気読み */
	if( data ) *data = ret_data; else if( ret_data ) free( ret_data );
	if( size ) *size = ret_size;
	remove( fnm ); /* テンポラリファイル削除 */
	return ret_size;
}

extern char* libc_readcsvline( const char *src,char *dst,size_t len )
{
	char *ptr = (char*)src,esc = ',';
	int num = 0;

	if( dst ) dst[0] = '\0'; /* INIT */
	if( !src || !dst || len <= 0 ) return NULL; /* FATAL */

	if( *ptr == '"' ){ esc = '"'; ptr++; }

	while( *ptr != '\0' && *ptr != esc ){
		if( *ptr == '\r' || *ptr == '\n' ){ /* 改行の扱い */
			if( esc == ',' ) break; /* ptr++; continue; */
		}
		else if( *ptr == '\\' && *(ptr + 1) == ',' ) ptr++; /* \, */
		if( num + 1 < len ){
			if( (dst[num] = *ptr) == '\'' ) dst[num] = '`';
			num++; /* DST INC */
		}ptr++; /* SRC INC */
	}
	dst[num] = '\0'; /* COPY FINISH */
	
	if( *ptr == '\0' ) return ptr; /* END */
	if( *ptr == ',' || *(++ptr) == ',' ) return ++ptr; /* INC */

	while( *ptr != '\0' && (*ptr == '\r' || *ptr == '\n') ){
		ptr++; /* GO NEXT DATA */
	}return ptr; /* COMPLETE */
}

static struct{ char han; const char *zen; }HANZEN[] = {
	{' ',"　"},{'!',"！"},{'"',"”"},{'#',"＃"},{'$',"＄"},{'%',"％"},{'&',"＆"},{'\'',"’"},
	{'(',"（"},{')',"）"},{'*',"＊"},{'+',"＋"},{',',"、"},{'-',"－"},{'.',"。"},{'/',"／"},
	{':',"："},{';',"；"},{'<',"＜"},{'=',"＝"},{'>',"＞"},{'?',"？"},{'@',"＠"},{'[',"［"},
	{'\\',"￥"},{']',"］"},{'^',"＾"},{'_',"＿"},{'`',"‘"},{'{',"｛"},{'|',"｜"},{'}',"｝"},{'~',"～"}
};

/* 可能な限りの半角→全角変換 */
extern char* libc_han2zenkaku( const char *src,char *dst )
{
	int i,j,x,y;
	if( dst ) dst[0] = '\0';
	if( strnull(src) ) return NULL;
	if( !dst && (dst = (char*)malloc( strlen( src ) * 3 + 1 )) == NULL ) return NULL;

	for( i = 0,j = 0; src[i] != '\0'; i++ ){
		if( (unsigned char)src[i] >= 0x80 ){ /* 全角 */
			if( (unsigned char)src[i] >= 0xE0 ){
				dst[j++] = src[i];
				dst[j++] = src[i + 1];
				dst[j++] = src[i + 2];
				i += 2;
			}else if( (unsigned char)src[i] != 0x5C ){
				dst[j++] = src[i];
				dst[j++] = src[i + 1];
				i++;
			}else{
				dst[j++] = src[i];
			}
		}else{ /* 半角現る */
			if( src[i] >= 'A' && src[i] <= 'Z' ){
				dst[j++] = 0xEF;
				dst[j++] = 0xBC;
				dst[j++] = 0xA1 + (src[i] - 'A');
			}
			else if( src[i] >= 'a' && src[i] <= 'z' ){
				dst[j++] = 0xEF;
				dst[j++] = 0xBD;
				dst[j++] = 0x81 + (src[i] - 'a');
			}
			else if( src[i] >= '0' && src[i] <= '9' ){
				dst[j++] = 0xEF;
				dst[j++] = 0xBC;
				dst[j++] = 0x90 + (src[i] - '0');
			}
			else{
				for( x = 0; x < countof(HANZEN); x++ ){
					if( src[i] == HANZEN[x].han ){
						y = strlen( HANZEN[x].zen );
						memcpy( dst + j,HANZEN[x].zen,y );
						j += y; break;
					}
				}
				if( x >= countof(HANZEN) ) dst[j++] = src[i]; /* GIVE UP */
			}
		}
	}dst[j] = '\0';
	return dst;
}

/* 可能な限りの全角→半角変換 */
extern char* libc_zen2hankaku( const char *src,char *dst )
{
	int i,j,x;
	if( dst ) dst[0] = '\0';
	if( strnull(src) ) return NULL;
	if( !dst && (dst = (char*)malloc( strlen( src ) + 1 )) == NULL ) return NULL;

	for( i = 0,j = 0; src[i] != '\0'; i++ ){
		if( (unsigned char)src[i] < 0x80 ){ /* 半角 */
			dst[j++] = src[i]; continue;
		}
		if( (unsigned char)src[i] == 0xEF &&
			(unsigned char)src[i + 1] == 0xBC &&
			(unsigned char)src[i + 2] >= 0x90 &&
			(unsigned char)src[i + 2] <= 0x99 ){
			dst[j++] = '0' + ((unsigned char)src[i + 2] - 0x90);
			i += 2; continue;
		}
		if( (unsigned char)src[i] == 0xEF &&
			(unsigned char)src[i + 1] == 0xBC &&
			(unsigned char)src[i + 2] >= 0xA1 &&
			(unsigned char)src[i + 2] <= 0xBA ){
			dst[j++] = 'A' + ((unsigned char)src[i + 2] - 0xA1);
			i += 2; continue;
		}
		if( (unsigned char)src[i] == 0xEF &&
			(unsigned char)src[i + 1] == 0xBD &&
			(unsigned char)src[i + 2] >= 0x81 &&
			(unsigned char)src[i + 2] <= 0x9A ){
			dst[j++] = 'a' + ((unsigned char)src[i + 2] - 0x81);
			i += 2; continue;
		}
		for( x = 0; x < countof(HANZEN); x++ ){
			if( strncmp( &(src[i]),HANZEN[x].zen,strlen( HANZEN[x].zen ) ) == 0 ){
				dst[j++] = HANZEN[x].han; break;
			}
		}
		if( (unsigned char)src[i] >= 0xE0 ){
			if( x >= countof(HANZEN) ){
				dst[j++] = src[i];
				dst[j++] = src[i + 1];
				dst[j++] = src[i + 2];
			}i += 2;
		}else{
			if( x >= countof(HANZEN) ){
				dst[j++] = src[i];
				dst[j++] = src[i + 1];
			}i++;
		}
	}dst[j] = '\0';
	return dst;
}

