#CBB_TOP_BUILDDIR = $(shell pwd)
$(eval CBB_TOP_BUILDDIR := $(abspath $(CURDIR)))
$(info $(CBB_TOP_BUILDDIR))
include $(CBB_TOP_BUILDDIR)/build/linux/opengauss/Makefile.global

SUBDIRS = src

# Supress parallel build to avoid depencies in the subdirectories.
.NOTPARALLEL:

$(recurse)