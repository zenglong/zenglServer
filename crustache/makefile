CC = gcc
AR = ar

ARFLAGS = rc
CFLAGS = -g3 -ggdb -O0 -std=c99
STATIC_CFLAGS = $(CFLAGS) -fvisibility=hidden -fPIC

SRCS = buffer.c crustache.c houdini_html.c stack.c
OBJS = buffer.o crustache.o houdini_html.o stack.o

libcrustache.a: $(OBJS)
		$(AR) $(ARFLAGS) libcrustache.a $(OBJS)

$(OBJS): $(SRCS) buffer.h crustache.h houdini.h html_unescape.h stack.h
		$(CC) $(STATIC_CFLAGS) -c $(SRCS)

clean:
		rm -fv libcrustache.a
		rm -fv *.o

