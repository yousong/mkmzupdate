#
# Copyright 2016 (c) Yousong Zhou
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

mkmzupdate: $(OBJS)
	$(CC) -o $@ $(OBJS)

clean:
	rm -vf *.o
	rm -vf mkmzupdate
