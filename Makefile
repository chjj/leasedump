# Makefile - makefile for leasedump
# Copyright (c) 2024, Christopher Jeffrey (MIT License).
# https://github.com/chjj/leasedump

#
# Default Rule
#

all: leasedump leasedump.8

#
# Rules
#

leasedump.o: leasedump.c Makefile
	$(CC) -c -DNDEBUG $(CPPFLAGS) -Wall -Wextra -O3 $(CFLAGS) leasedump.c

leasedump: leasedump.o Makefile
	$(CC) -o $@ $(LDFLAGS) leasedump.o

leasedump.8: leasedump.pod Makefile
	pod2man --section 8                    \
		--date "23 April 2024"               \
		--name "LEASEDUMP"                   \
		--center "User Contributed Software" \
		leasedump.pod leasedump.8

clean: Makefile
	-rm -f leasedump leasedump.o leasedump.8
