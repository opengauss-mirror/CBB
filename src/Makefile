$(eval CBB_TOP_BUILDDIR := $(abspath $(CURDIR)/..))
$(info $(CBB_TOP_BUILDDIR))
BASE_BUILD_PATH = $(CBB_TOP_BUILDDIR)/build/linux/opengauss

subdirs = src
include $(BASE_BUILD_PATH)/Makefile.global

VERSION = 1

DESTDIR = $(BASE)/../output

include $(BASE_BUILD_PATH)/common.mk

LDFLAGS += $(addprefix -L,$(3RD_LIB_PATH))
LDFLAGS += -L${SECURE_LIB}
LDFLAGS += -L${SSL_LIB}
LIBS = -lpthread -ldl -lrt -Wl,--whole-archive -lsecurec -Wl,--no-whole-archive -lssl -lcrypto


SOURCE=$(wildcard ./*c ./cm_concurrency/*.c ./cm_defines/*.c ./cm_mes/*.c ./cm_network/*.c ./cm_protocol/*.c \
./cm_security/*.c ./cm_struct/*.c ./cm_time/*.c ./cm_types/*.c ./cm_utils/*.c)

OBJS = $(patsubst %.c,%.o,$(SOURCE))

DESTDIR = $(CBB_TOP_BUILDDIR)/output
DEST_LIB_DIR = $(DESTDIR)/lib

all: libcbb_static.a libcbb.so

libcbb.so: $(OBJS)
	$(CC) -fPIC -shared $(LDFLAGS) $(LIBS) -o libcbb.so  $(OBJS)
	mkdir -p $(DESTDIR)/lib && mv $(CBB_TOP_BUILDDIR)/src/libcbb.so $(DEST_LIB_DIR) && \
	mv $(CBB_TOP_BUILDDIR)/src/libcbb_static.a $(DEST_LIB_DIR)

libcbb_static.a: $(OBJS)
	ar crs $@ $^

install:all

clean:
	rm -f $(OBJS) */*.d $(DEST_LIB_DIR)/libcbb_static.a $(DEST_LIB_DIR)/libcbb.so
distclean: clean

maintainer-clean: distclean
