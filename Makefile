include mak/defs.mak
-include config.mak

.PHONY: tests
.PHONY: prereqs

##==============================================================================
##
## Check whether ./configure was run (creates ./config)
##
##==============================================================================

ifndef OE_CONFIGURED
$(error Please run ./configure first)
endif

##==============================================================================
##
## build:
##
##==============================================================================

DIRS = 3rdparty gen host libc enclave crypto elf sign tests

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NEWLINE) )

##==============================================================================
##
## depend:
##
##==============================================================================

depend:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) depend $(NEWLINE) )

##==============================================================================
##
## clean:
##
##==============================================================================

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NEWLINE) )
	rm -rf bin
	rm -rf lib
	rm -rf obj

##==============================================================================
##
## distclean:
##
##==============================================================================

DISTNAME=openenclave-$(OE_VERSION)

distclean: clean
	rm -rf include/musl
	rm -rf include/stlport
	$(MAKE) -s -C prereqs distclean 2> /dev/null
	$(MAKE) -C 3rdparty distclean
	rm -rf lib bin
	rm -f include/enclave/oecommon
	rm -f include/enclave/oeinternal
	rm -f include/host/oecommon
	rm -f include/host/oeinternal
	rm -f $(DISTNAME).tar.gz
	rm -f $(DISTNAME)
	rm -f config.mak

##==============================================================================
##
## tests:
##
##==============================================================================

tests:
	$(MAKE) -s -C tests tests

##==============================================================================
##
## world:
##
##==============================================================================

world:
	$(MAKE) -s clean
	$(MAKE)
	$(MAKE) -s -C tests tests

##==============================================================================
##
## sub:
##
##==============================================================================

SUB = $(shell find . -name '*.[ch]') $(shell find . -name '*.cpp')

sub:
	./scripts/sub $(SUB)

##==============================================================================
##
## dist:
##
##==============================================================================

dist:
	@ $(MAKE) -s -f mak/dist.mak DISTNAME=$(DISTNAME) TOP=$(TOP)

##==============================================================================
##
## big:
##
##==============================================================================

big:
	find . -size +1000

##==============================================================================
##
## prereqs:
##
##==============================================================================

prereqs:
	$(MAKE) -C prereqs
	$(MAKE) -C prereqs install

##==============================================================================
##
## install:
##
##==============================================================================

install:
	@ ./scripts/install

##==============================================================================
##
## check:
##
##==============================================================================

CHECKDIR=$(TMPDIR)/$(DISTNAME)

check:
	$(MAKE) -s -f mak/check.mak DISTNAME=$(DISTNAME)

##==============================================================================
##
## cloc:
##
##     Count lines of orignal code:
##
##==============================================================================

CLOC += $(wildcard enclave/*.c)
CLOC += $(wildcard host/*.c)
CLOC += $(wildcard include/enclave/openenclave.h)
CLOC += $(wildcard include/host/openenclave.h)
CLOC += $(wildcard include/oecommon/*.h)
CLOC += $(wildcard include/oeinternal/*.h)

cloc:
	cloc $(CLOC)

CLOCPLUS += $(CLOC)
CLOCPLUS += $(wildcard common/*.c)
CLOCPLUS += $(wildcard libc/*.c)
CLOCPLUS += $(wildcard include/enclave/libc/*.h)

clocplus:
	cloc $(CLOCPLUS)
