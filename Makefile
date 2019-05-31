MAKETOP	=	../Make
MKTYPE	=	StaticLibrary
MKLANG	=	C
TARGET	=	libc.a
SRCS	=	libc.c
CC_DBG	+=	-g
#CC_OPT	+=	-Wno-deprecated-declarations

include ${MAKETOP}/Makefile
