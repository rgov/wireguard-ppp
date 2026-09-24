CC ?= cc
BUILD ?= build
CPPFLAGS += -Isrc -Iwireguard-lwip/src -Ilwip/src/include
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu99 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare

LW = lwip/src
WG = wireguard-lwip/src

LW_CORE_SRCS = \
    $(LW)/core/def.c \
    $(LW)/core/inet_chksum.c \
    $(LW)/core/init.c \
    $(LW)/core/ip.c \
    $(LW)/core/ipv4/ip4_addr.c \
    $(LW)/core/mem.c \
    $(LW)/core/memp.c \
    $(LW)/core/netif.c \
    $(LW)/core/pbuf.c \
    $(LW)/core/timeouts.c

LW_PPP_SRCS = \
    $(LW)/netif/ppp/auth.c \
    $(LW)/netif/ppp/fsm.c \
    $(LW)/netif/ppp/ipcp.c \
    $(LW)/netif/ppp/lcp.c \
    $(LW)/netif/ppp/magic.c \
    $(LW)/netif/ppp/ppp.c \
    $(LW)/netif/ppp/pppos.c \
    $(LW)/netif/ppp/utils.c

WG_SRCS = \
    $(WG)/crypto.c \
    $(wildcard $(WG)/crypto/refc/*.c) \
    $(WG)/wireguard.c \
    $(WG)/wireguardif.c

SRCS = \
    $(LW_CORE_SRCS) \
    $(LW_PPP_SRCS) \
    $(WG_SRCS) \
    src/config.c \
    src/main.c \
    src/platform.c

OBJECTS = $(SRCS:%.c=$(BUILD)/%.o)

.PHONY: all clean
all: $(BUILD)/wg-ppp

$(BUILD)/wg-ppp: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Workaround for diagnostics being logged to stdout
$(BUILD)/$(WG)/wireguardif.o: CPPFLAGS += -include compat/printf_to_stderr.h

$(BUILD)/%.o: %.c Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

clean:
	rm -rf $(BUILD)

-include $(OBJECTS:.o=.d)
