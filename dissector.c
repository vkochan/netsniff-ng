/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010, 2011, 2012 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "built_in.h"
#include "tprintf.h"
#include "pkt_buff.h"
#include "proto.h"
#include "dissector.h"
#include "dissector_eth.h"
#include "dissector_sll.h"
#include "dissector_80211.h"
#include "dissector_netlink.h"
#include "linktype.h"

int dissector_set_print_type(void *ptr, int type)
{
	struct protocol *proto;

	for (proto = ptr; proto; proto = proto->next) {
		if (type & PRINT_NORM) {
			proto->process = proto->print_full;
		} else if (type == PRINT_LESS) {
			proto->process = proto->print_less;
		} else {
			proto->process = NULL;
		}
	}

	return 0;
}

static void dissector_main(struct pkt_buff *pkt, struct protocol *start,
			   struct protocol *end)
{
	struct protocol *dissector;

	if (!start)
		return;

	for (pkt->dissector = start; pkt->dissector; ) {
		if (unlikely(!pkt->dissector->process))
			break;

		dissector = pkt->dissector;
		pkt->dissector = NULL;
		dissector->process(pkt);
	}

	if (end && likely(end->process))
		end->process(pkt);
}

void dissector_entry_point(uint8_t *packet, size_t len, int linktype, int mode,
			   struct sockaddr_ll *sll)
{
	struct pkt_buff pkt_tmp, pkt_hex, pkt_ascii;
	struct protocol *proto_start, *proto_end;
	struct pkt_buff *pkt, *pkt_orig;

	if (mode == PRINT_NONE)
		return;

	pkt = pkt_alloc(packet, len);
	pkt->link_type = linktype;
	pkt->sll = sll;

	switch (linktype) {
	case LINKTYPE_EN10MB:
	case ___constant_swab32(LINKTYPE_EN10MB):
		proto_start = dissector_get_ethernet_entry_point();
		proto_end = dissector_get_ethernet_exit_point();
		break;
	case LINKTYPE_IEEE802_11_RADIOTAP:
	case ___constant_swab32(LINKTYPE_IEEE802_11_RADIOTAP):
	case LINKTYPE_IEEE802_11:
	case ___constant_swab32(LINKTYPE_IEEE802_11):
		proto_start = dissector_get_ieee80211_entry_point();
		proto_end = dissector_get_ieee80211_exit_point();
		break;
	case LINKTYPE_NETLINK:
	case ___constant_swab32(LINKTYPE_NETLINK):
		proto_start = dissector_get_netlink_entry_point();
		proto_end = dissector_get_netlink_exit_point();
		break;
	case LINKTYPE_LINUX_SLL:
	case ___constant_swab32(LINKTYPE_LINUX_SLL):
		proto_start = dissector_get_sll_entry_point();
		proto_end = dissector_get_sll_exit_point();
		break;
	default:
		proto_start = &none_ops;
		proto_end = NULL;
		break;
	};

	if (mode & PRINT_HEADERS) {
		pkt_orig = pkt_clone(&pkt_tmp, pkt);
	} else {
		pkt_orig = pkt;
	}

	dissector_main(pkt, proto_start, proto_end);

	if (mode & PRINT_HEX) {
		hex(pkt_clone(&pkt_hex, pkt_orig));
	}

	if (mode & PRINT_ASCII) {
		ascii(pkt_clone(&pkt_ascii, pkt_orig));
	}

	tprintf_flush();
	pkt_free(pkt);
}

void dissector_init_all(int fnttype)
{
	dissector_init_ethernet(fnttype);
	dissector_init_ieee80211(fnttype);
	dissector_init_netlink(fnttype);
	dissector_init_sll(fnttype);
}

void dissector_cleanup_all(void)
{
	dissector_cleanup_ethernet();
	dissector_cleanup_ieee80211();
	dissector_cleanup_netlink();
	dissector_cleanup_sll();
}
