PLUGIN_NAME=packet-atlas
WIRESHARK_SRC_DIR=/usr/include/wireshark
INC_GLIB=/usr/include/glib-2.0

SRCS=packet-atlas.c plugin.c
CC=gcc
OBJS=$(foreach src, $(SRCS), $(src:.c=.o))

INC_DIRS   = -I. -I$(INC_GLIB)
CFLAGS = $(INC_DIRS) -DHAVE_CONFIG_H -I$(WIRESHARK_SRC_DIR) -I/usr/local/include -I/usr/local/include -I/usr/local/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -I/usr/lib/i386-linux-gnu/glib-2.0/include -fPIC -DPIC

LDFLAGS = -Wl,--rpath -Wl,/usr/local/lib -Wl,--rpath -Wl,/usr/local/lib -L/usr/local/lib -L$(WIRESHARK_SRC_DIR)/epan -L. -lgmodule-2.0 -ldl -lglib-2.0  -pthread -Wl,--export-dynamic -Wl,-soname -Wl,$(PLUGIN_NAME).so


all: $(PLUGIN_NAME).so

$(PLUGIN_NAME).so : $(OBJS) $(SRCS)
	$(CC) -shared $(OBJS) $(LDFLAGS) -o $@


plugin.c: moduleinfo.h Makefile.am Makefile.common
	$(MAKE) -f Makefile.am

clean:
	rm -f $(PLUGIN) $(OBJS) *.so *.o
