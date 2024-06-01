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
LDFLAGS += -L${LZ4_LIB}
LIBS = -lpthread -ldl -lrt -llz4 -Wl,--whole-archive -lsecurec -Wl,--no-whole-archive -lssl -lcrypto


SOURCE=$(wildcard ./*c ./cm_concurrency/*.c ./cm_defines/*.c ./cm_mes/*.c ./cm_network/*.c ./cm_protocol/*.c \
./cm_security/*.c ./cm_struct/*.c ./cm_time/*.c ./cm_types/*.c ./cm_utils/*.c ./cm_utils/protocol/*.c ./cm_res/*.c \
./ddes_json/*.c ./ddes_lexer/*.c ./ddes_perctrl/interface/*.c ./cm_compress/*.c ./cm_mec_adapter/*.c \
/ddes_fi/*.c)

OBJS = $(patsubst %.c,%.o,$(SOURCE))

DESTDIR = $(CBB_TOP_BUILDDIR)/output
DEST_LIB_DIR = $(DESTDIR)/lib

all: libcbb.so libcbb.a libcbb_static.a

libcbb.so: $(OBJS)
	$(CC) -fPIC -shared $(LDFLAGS) $(LIBS) -o libcbb.so  $(OBJS)
	mkdir -p $(DESTDIR)/lib && mv $(CBB_TOP_BUILDDIR)/src/libcbb.so $(DEST_LIB_DIR)

libcbb.a: $(OBJS)
	ar crs $@ $^
	mkdir -p $(DESTDIR)/lib && mv $(CBB_TOP_BUILDDIR)/src/libcbb.a $(DEST_LIB_DIR)

libcbb_static.a: $(OBJS)
	ar crs $@ $^
	mkdir -p $(DESTDIR)/lib && mv $(CBB_TOP_BUILDDIR)/src/libcbb_static.a $(DEST_LIB_DIR)
    
install:all

clean:
	rm -f $(OBJS) */*.d $(DEST_LIB_DIR)/libcbb.a $(DEST_LIB_DIR)/libcbb.so $(DEST_LIB_DIR)/libcbb_static.a
distclean: clean

maintainer-clean: distclean
