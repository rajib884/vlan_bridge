# Makefile for vlan_bridge
#
# Cross-compiles a Windows x64 .exe from Linux using mingw-w64 and the Npcap
# SDK. The SDK is downloaded automatically on first build.
#
# Linux (cross-compile):
#   sudo apt-get install gcc-mingw-w64-x86-64
#   make                      # fetches Npcap SDK if needed, builds $(TARGET)
#
# Native MinGW / MSYS2 on Windows (SDK already installed):
#   make CC=gcc SDK=/c/npcap-sdk
#
# Common overrides:
#   make CC=x86_64-w64-mingw32-gcc     # if your mingw symlink isn't broken
#   make SDK_ARCH=ARM64                # Windows-on-ARM target
#   make clean | make distclean        # remove binary | binary + SDK

# ── configuration ───────────────────────────────────────────────────────────
# The bare x86_64-w64-mingw32-gcc symlink is a broken alternatives loop on some
# Debian/Ubuntu images, so default to the concrete -posix variant. Use
# $(origin) so command-line/environment CC still wins but make's built-in
# default of "cc" (host compiler) does not.
ifeq ($(origin CC),default)
CC = x86_64-w64-mingw32-gcc-posix
endif
# Resource compiler for the GUI (matches the mingw toolchain prefix).
WINDRES  ?= x86_64-w64-mingw32-windres
# windres shells out to a preprocessor; point it at $(CC) explicitly because the
# bare x86_64-w64-mingw32-gcc symlink is broken on some images.
WINDRESFLAGS ?= --preprocessor=$(CC) --preprocessor-arg=-E \
                --preprocessor-arg=-xc --preprocessor-arg=-DRC_INVOKED
CFLAGS   ?= -O2 -Wall -Wextra
TARGET   ?= vlan_bridge.exe
SRCS      = vlan_bridge.c engine.c fast_log.c
HDRS      = engine.h fast_log.h

# GUI front-end (native Win32).
GUI_TARGET ?= vlan_bridge_gui.exe
GUI_SRCS    = vlan_bridge_gui.c engine.c fast_log.c
GUI_RC      = vlan_bridge_gui.rc
GUI_LIBS    = -lcomctl32 -lgdi32 -luser32

# Npcap SDK: location, version, and auto-download URL.
SDK          ?= npcap-sdk
SDK_VERSION  ?= 1.13
SDK_URL      ?= https://npcap.com/dist/npcap-sdk-$(SDK_VERSION).zip
# Lib subdir: x64 | ARM64 | (empty for 32-bit, whose import libs sit in Lib/).
SDK_ARCH     ?= x64

# wpcap is linked DELAY-loaded, not directly: Npcap keeps wpcap.dll in
# System32\Npcap, which is off the default DLL search path, so a normal import
# makes the loader fail before main() runs. The delay-import library below is
# generated from wpcap_delay.def; engine_load_npcap() loads the real DLL by
# absolute path before the first pcap call. -ldelayimp supplies the helper.
DLLTOOL    ?= x86_64-w64-mingw32-dlltool
DELAY_DEF   = wpcap_delay.def
DELAY_LIB   = libwpcap_delay.a

INCLUDES  = -I"$(SDK)/Include"
LIBS      = -L. -lwpcap_delay -ldelayimp -lws2_32 -liphlpapi

# ── targets ─────────────────────────────────────────────────────────────────
.PHONY: all gui sdk clean distclean

all: $(TARGET)

# Delay-import library for wpcap.dll. Built from a checked-in .def so this
# works when cross-compiling too (no wpcap.dll present on the build host).
$(DELAY_LIB): $(DELAY_DEF)
	$(DLLTOOL) -d $(DELAY_DEF) -y $@

$(TARGET): $(SRCS) $(HDRS) $(DELAY_LIB) | $(SDK)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(INCLUDES) $(LIBS)

# GUI: compile the manifest resource, then link the Win32 front-end.
gui: $(GUI_TARGET)

$(GUI_TARGET): $(GUI_SRCS) $(GUI_RC) vlan_bridge_gui.manifest $(HDRS) $(DELAY_LIB) | $(SDK)
	$(WINDRES) $(WINDRESFLAGS) $(GUI_RC) -O coff -o gui_res.o
	$(CC) $(CFLAGS) -mwindows -o $@ $(GUI_SRCS) gui_res.o $(INCLUDES) $(LIBS) $(GUI_LIBS)
	rm -f gui_res.o

# Download & unpack the Npcap SDK (order-only prereq: runs only if missing).
sdk: $(SDK)

$(SDK):
	@echo ">> Fetching Npcap SDK $(SDK_VERSION)..."
	curl -sSL -o npcap-sdk.zip "$(SDK_URL)"
	mkdir -p "$(SDK)"
	unzip -oq npcap-sdk.zip -d "$(SDK)"
	rm -f npcap-sdk.zip

clean:
	rm -f $(TARGET) $(GUI_TARGET) gui_res.o $(DELAY_LIB)

distclean: clean
	rm -rf $(SDK) npcap-sdk.zip
