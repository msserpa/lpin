##############################################################
#
#                   DO NOT EDIT THIS FILE!
#
##############################################################

MYVER=$(shell /opt/pin/pin -version |grep Pin)

ifeq ($(MYVER), Pin 2.10) # old pin versions use different makefile system

TOOL_CXXFLAGS += -Wall -g -std=c++0x -Wno-error

TOOL_ROOTS := motivation

PIN_HOME = /opt/pin
PIN_KIT=$(PIN_HOME)
KIT=1

include $(PIN_HOME)/source/tools/makefile.gnu.config
CXXFLAGS ?= $(DBG) $(OPT) $(TOOL_CXXFLAGS) -DOLD_PIN
PIN=$(PIN_HOME)/pin

CXX=g++

TOOLS = $(TOOL_ROOTS:%=$(OBJDIR)%$(PINTOOL_SUFFIX))

all: tools
tools: $(OBJDIR) $(TOOLS)


$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)%.o : %.cpp
	$(CXX) -c $(CXXFLAGS) $(PIN_CXXFLAGS) ${OUTOPT}$@ $<

$(TOOLS): %$(PINTOOL_SUFFIX) : %.o
	${PIN_LD} $(PIN_LDFLAGS) $(LINK_DEBUG) ${LINK_OUT}$@ $< ${PIN_LPATHS} $(PIN_LIBS) $(DBG)


clean:
	rm -rf $(OBJDIR)


else # new pin versions

# If the tool is built out of the kit, PIN_ROOT must be specified in the make invocation and point to the kit root.

override PIN_ROOT = /opt/pin

ifdef PIN_ROOT
CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
else
CONFIG_ROOT := ../Config
endif
include $(CONFIG_ROOT)/makefile.config
include makefile.rules
include $(TOOLS_ROOT)/Config/makefile.default.rules

endif

##############################################################
#
#                   DO NOT EDIT THIS FILE!
#
##############################################################
