# I am not very good at Makefiles.

CC = gcc
INCLUDES = -I. 
INCLUDES += -I/usr/src/linux-5.4.44-gheap/include
CFLAGS = -Wall -Wextra -Werror -O3 $(INCLUDES) -DGLOBAL_HEAP
CPPFLAGS = $(CFLAGS)

.c.o:
	@ echo -e "  CC [C] `pwd`/$@"
	@ $(CC) -o $@ -c $(CFLAGS) $<

.o:
	@ echo -e "  CC [L] `pwd`/$@"
	@ $(CC) -o $@ $< $(CFLAGS) $(LDLIBS)

.c:
	@ echo -e "  CC \t `pwd`/$@"
	@ $(CC) -o $@ $(CFLAGS) $<

MALLOCLIB = libmalloc.a

MALLOCLIB_OBJ = malloc.o

all: $(MALLOCLIB)

$(MALLOCLIB) : $(MALLOCLIB_OBJ)
	@ echo -e "  CC [L] `pwd`/$@"
	ar rv $(MALLOCLIB) $(MALLOCLIB_OBJ)


clean:
	rm -f $(MALLOCLIB) $(MALLOCLIB_OBJ)
