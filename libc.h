#ifndef __libc_h__
#define __libc_h__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define strnull(x) (x == NULL || x[0] == '\0')
#define countof(x) sizeof(x) / sizeof(x[0])

typedef struct{
	char *name;
	char *data;
	size_t size;
	char *file;
}libc_item;

typedef struct{
	int count;
	libc_item *items;
}libc_array;

extern unsigned long libc_longtime( void );
extern char* libc_stringtime( const struct tm *src,char *dst,size_t len );
extern char* libc_readfile( const char *path,size_t *size );
extern int libc_writefile( const char *path,const char *mode,const char *data,size_t size );
extern int libc_logfile( const char *path,const char *fmt, ... );
extern FILE* libc_openfile( const char *path,const char *mode );
extern int libc_closefile( FILE *stream );

extern libc_array* libc_readconfigfile( const char *path );
extern libc_array* libc_readcgiparams( void );
extern libc_array* libc_readcookieparams( void );
extern libc_array* libc_readsinglepart( char *mem,size_t len,char sep );
extern libc_array* libc_readmultipart( char *mem,size_t len );
extern libc_array* libc_readjsonpart( char *mem,size_t len );
extern char* libc_searchdata( const libc_array *array,const char *name,int *index );
extern void libc_freearray( libc_array *array );

extern char* libc_encodeurl( const char *src,char *dst );
extern char* libc_decodeurl( const char *src,char *dst );
extern char* libc_encodexor( const char *src,char *dst );
extern char* libc_decodexor( const char *src,char *dst );
extern unsigned char* libc_encodehmac( const char *src,const char *key,int evp,size_t *bin );
extern unsigned char* libc_encodebase64( const unsigned char *str,int length,int *ret_length,int url_safe );
extern unsigned char *libc_decodebase64( const unsigned char *str,int length,int *ret_length,int url_safe );

extern int libc_sendrecv( const char *host,const char *port,
	const char *senddata,size_t sendsize,char **recvdata,size_t *recvsize );
extern size_t libc_httpsplit( char *http,size_t hlen,char **head,char **body );
extern int libc_getcookievalue( char *http,const char *name,char *value );
extern int libc_gethiddenvalue( char *http,const char *name,char *value );

extern char* libc_readcsvline( const char *src,char *dst,size_t len );
extern char* libc_han2zenkaku( const char *src,char *dst );
extern char* libc_zen2hankaku( const char *src,char *dst );

extern void* libc_opendatabase( const char *param );
extern void libc_closedatabase( void *handle );
extern int libc_execdatabase( void *handle,const char *sql,void **out );
extern char* libc_readdatabase( void *result,int row,int col );
extern void libc_freedatabase( void *result );

#ifdef __cplusplus
}   /* extern "C" */
#endif

#endif /* __libc_h__ */
