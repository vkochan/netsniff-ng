/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009 - 2013 Daniel Borkmann.
 * Copyright 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#ifndef PCAP_IO_H
#define PCAP_IO_H

#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/filter.h>

#include "built_in.h"
#include "die.h"
#include "dev.h"
#include "ioops.h"
#include "linktype.h"

#define TCPDUMP_MAGIC				0xa1b2c3d4
#define ORIGINAL_TCPDUMP_MAGIC			TCPDUMP_MAGIC
#define NSEC_TCPDUMP_MAGIC			0xa1b23c4d
#define ORIGINAL_TCPDUMP_MAGIC_LL		0xb1b2c3d4	/* Internal dummy just for mapping */
#define NSEC_TCPDUMP_MAGIC_LL			0xb1b23c4d	/* Internal dummy just for mapping */
#define KUZNETZOV_TCPDUMP_MAGIC			0xa1b2cd34
#define BORKMANN_TCPDUMP_MAGIC			0xa1e2cb12

#define PCAP_VERSION_MAJOR			2
#define PCAP_VERSION_MINOR			4
#define PCAP_DEFAULT_SNAPSHOT_LEN		65535

#define PCAP_TSOURCE_SOFTWARE			1
#define PCAP_TSOURCE_SYS_HARDWARE		2
#define PCAP_TSOURCE_RAW_HARDWARE		3

struct pcap_filehdr {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t  thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t linktype;
};

struct pcap_timeval {
	int32_t tv_sec;
	int32_t tv_usec;
};

struct pcap_timeval_ns {
	int32_t tv_sec;
	int32_t tv_nsec;
};

struct pcap_ll {
	uint16_t pkttype;
	uint16_t hatype;
	uint16_t len;
	uint8_t addr[8];
	uint16_t protocol;
};

struct pcap_pkthdr {
	struct pcap_timeval ts;
	uint32_t caplen;
	uint32_t len;
};

struct pcap_pkthdr_ns {
	struct pcap_timeval_ns ts;
	uint32_t caplen;
	uint32_t len;
};

struct pcap_pkthdr_ll {
	struct pcap_timeval ts;
	uint32_t caplen;
	uint32_t len;
	struct pcap_ll ll;
};

struct pcap_pkthdr_ns_ll {
	struct pcap_timeval_ns ts;
	uint32_t caplen;
	uint32_t len;
	struct pcap_ll ll;
};

struct pcap_pkthdr_kuz {
	struct pcap_timeval ts;
	uint32_t caplen;
	uint32_t len;
	uint32_t ifindex;
	uint16_t protocol;
	uint8_t pkttype;
};

struct pcap_pkthdr_bkm {
	struct pcap_timeval_ns ts;
	uint32_t caplen;
	uint32_t len;
	uint16_t tsource;
	uint16_t ifindex;
	uint16_t protocol;
	uint8_t hatype;
	uint8_t pkttype;
};

typedef union {
	struct pcap_pkthdr		ppo;
	struct pcap_pkthdr_ns		ppn;
	struct pcap_pkthdr_ll		ppo_ll;
	struct pcap_pkthdr_ns_ll	ppn_ll;
	struct pcap_pkthdr_kuz		ppk;
	struct pcap_pkthdr_bkm		ppb;
	uint8_t				raw;
} pcap_pkthdr_t;

enum pcap_type {
	DEFAULT		  =	ORIGINAL_TCPDUMP_MAGIC,
	NSEC		  =	NSEC_TCPDUMP_MAGIC,
	DEFAULT_LL	  =	ORIGINAL_TCPDUMP_MAGIC_LL,
	NSEC_LL		  =	NSEC_TCPDUMP_MAGIC_LL,
	KUZNETZOV	  =	KUZNETZOV_TCPDUMP_MAGIC,
	BORKMANN	  =	BORKMANN_TCPDUMP_MAGIC,

	DEFAULT_SWAPPED	  =	___constant_swab32(ORIGINAL_TCPDUMP_MAGIC),
	NSEC_SWAPPED	  =	___constant_swab32(NSEC_TCPDUMP_MAGIC),
	DEFAULT_LL_SWAPPED =	___constant_swab32(ORIGINAL_TCPDUMP_MAGIC_LL),
	NSEC_LL_SWAPPED	  =	___constant_swab32(NSEC_TCPDUMP_MAGIC_LL),
	KUZNETZOV_SWAPPED =	___constant_swab32(KUZNETZOV_TCPDUMP_MAGIC),
	BORKMANN_SWAPPED  =	___constant_swab32(BORKMANN_TCPDUMP_MAGIC),
};

enum pcap_ops_groups {
	PCAP_OPS_RW = 0,
	PCAP_OPS_SG,
	PCAP_OPS_MM,
};

enum pcap_mode {
	PCAP_MODE_RD = 0,
	PCAP_MODE_WR,
};

struct pcap_file_ops {
	void (*init_once_pcap)(bool enforce_prio);
	int (*pull_fhdr_pcap)(int fd, uint32_t *magic, uint32_t *linktype);
	int (*push_fhdr_pcap)(int fd, uint32_t magic, uint32_t linktype);
	int (*prepare_access_pcap)(int fd, enum pcap_mode mode, bool jumbo);
	ssize_t (*write_pcap)(int fd, pcap_pkthdr_t *phdr, enum pcap_type type,
			      const uint8_t *packet, size_t len);
	ssize_t (*read_pcap)(int fd, pcap_pkthdr_t *phdr, enum pcap_type type,
			     uint8_t *packet, size_t len);
	void (*prepare_close_pcap)(int fd, enum pcap_mode mode);
	void (*fsync_pcap)(int fd);
};

struct pcap_io {
	uint32_t link_type;
	uint32_t magic;

	const struct pcap_file_ops *ops;
	enum pcap_ops_groups ops_type;
	enum pcap_type type;
	enum pcap_mode mode;
	const char *path;
	bool enforce_prio;
	bool jumbo;
	int fd;

	struct sock_fprog *bpf_ops;
	uint64_t truncated;
};

struct pcap_packet {
	pcap_pkthdr_t phdr;
	struct pcap_io *io;
	bool is_buf_alloc;
	uint32_t buf_len;
	uint8_t *buf;
};

extern const struct pcap_file_ops pcap_rw_ops __maybe_unused;
extern const struct pcap_file_ops pcap_sg_ops __maybe_unused;
extern const struct pcap_file_ops pcap_mm_ops __maybe_unused;

static inline void sockaddr_to_ll(const struct sockaddr_ll *sll,
				  struct pcap_ll *ll)
{
	ll->pkttype = cpu_to_be16(sll->sll_pkttype);
	ll->hatype = cpu_to_be16(sll->sll_hatype);
	ll->len = cpu_to_be16(sll->sll_halen);
	ll->protocol = sll->sll_protocol; /* already be16 */

	memcpy(ll->addr, sll->sll_addr, sizeof(ll->addr));
}

static inline void ll_to_sockaddr(const struct pcap_ll *ll,
				  struct sockaddr_ll *sll)
{
	sll->sll_pkttype = be16_to_cpu(ll->pkttype);
	sll->sll_hatype = be16_to_cpu(ll->hatype);
	sll->sll_halen = be16_to_cpu(ll->len);
	sll->sll_protocol = ll->protocol; /* stays be16 */

	memcpy(sll->sll_addr, ll->addr, sizeof(ll->addr));
}

static inline uint16_t tp_to_pcap_tsource(uint32_t status)
{
	if (status & TP_STATUS_TS_RAW_HARDWARE)
		return PCAP_TSOURCE_RAW_HARDWARE;
	else if (status & TP_STATUS_TS_SYS_HARDWARE)
		return PCAP_TSOURCE_SYS_HARDWARE;
	else if (status & TP_STATUS_TS_SOFTWARE)
		return PCAP_TSOURCE_SOFTWARE;
	else
		return 0;
}

static inline int pcap_devtype_to_linktype(int dev_type)
{
	switch (dev_type) {
	case ARPHRD_TUNNEL:
	case ARPHRD_TUNNEL6:
	case ARPHRD_LOOPBACK:
	case ARPHRD_SIT:
	case ARPHRD_IPDDP:
	case ARPHRD_IPGRE:
	case ARPHRD_IP6GRE:
	case ARPHRD_ETHER:
		return LINKTYPE_EN10MB;
	case ARPHRD_IEEE80211_RADIOTAP:
		return LINKTYPE_IEEE802_11_RADIOTAP;
	case ARPHRD_IEEE80211_PRISM:
	case ARPHRD_IEEE80211:
		return LINKTYPE_IEEE802_11;
	case ARPHRD_NETLINK:
		return LINKTYPE_NETLINK;
	case ARPHRD_EETHER:
		return LINKTYPE_EN3MB;
	case ARPHRD_AX25:
		return LINKTYPE_AX25;
	case ARPHRD_CHAOS:
		return LINKTYPE_CHAOS;
	case ARPHRD_PRONET:
		return LINKTYPE_PRONET;
	case ARPHRD_IEEE802_TR:
	case ARPHRD_IEEE802:
		return LINKTYPE_IEEE802;
	case ARPHRD_INFINIBAND:
		return LINKTYPE_INFINIBAND;
	case ARPHRD_ATM:
		return LINKTYPE_ATM_CLIP;
	case ARPHRD_DLCI:
		return LINKTYPE_FRELAY;
	case ARPHRD_ARCNET:
		return LINKTYPE_ARCNET_LINUX;
	case ARPHRD_CSLIP:
	case ARPHRD_CSLIP6:
	case ARPHRD_SLIP6:
	case ARPHRD_SLIP:
		return LINKTYPE_SLIP;
	case ARPHRD_PPP:
		return LINKTYPE_PPP;
	case ARPHRD_CAN:
		return LINKTYPE_CAN20B;
	case ARPHRD_ECONET:
		return LINKTYPE_ECONET;
	case ARPHRD_RAWHDLC:
	case ARPHRD_CISCO:
		return LINKTYPE_C_HDLC;
	case ARPHRD_FDDI:
		return LINKTYPE_FDDI;
	case ARPHRD_IEEE802154_MONITOR:
	case ARPHRD_IEEE802154:
		return LINKTYPE_IEEE802_15_4_LINUX;
	case ARPHRD_IRDA:
		return LINKTYPE_LINUX_IRDA;
	default:
		return LINKTYPE_NULL;
	}
}

static inline bool link_has_sll_hdr(uint32_t link_type)
{
	switch (link_type) {
	case LINKTYPE_NETLINK:
	case LINKTYPE_LINUX_SLL:
	case ___constant_swab32(LINKTYPE_NETLINK):
	case ___constant_swab32(LINKTYPE_LINUX_SLL):
		return true;
	default:
		return false;
	}
}

static inline int pcap_dev_to_linktype(const char *ifname)
{
	return pcap_devtype_to_linktype(device_type(ifname));
}

static inline void pcap_check_magic(uint32_t magic)
{
	switch (magic) {

	case ORIGINAL_TCPDUMP_MAGIC:
	case NSEC_TCPDUMP_MAGIC:
	case KUZNETZOV_TCPDUMP_MAGIC:
	case BORKMANN_TCPDUMP_MAGIC:

	case ___constant_swab32(ORIGINAL_TCPDUMP_MAGIC):
	case ___constant_swab32(NSEC_TCPDUMP_MAGIC):
	case ___constant_swab32(KUZNETZOV_TCPDUMP_MAGIC):
	case ___constant_swab32(BORKMANN_TCPDUMP_MAGIC):
		break;

	default:
		panic("This file has an unsupported pcap magic number(0x%x)\n", magic);
	}
}

static inline bool pcap_magic_is_swapped(uint32_t magic)
{
	bool swapped = false;

	switch (magic) {
	case ___constant_swab32(ORIGINAL_TCPDUMP_MAGIC):
	case ___constant_swab32(NSEC_TCPDUMP_MAGIC):
	case ___constant_swab32(KUZNETZOV_TCPDUMP_MAGIC):
	case ___constant_swab32(BORKMANN_TCPDUMP_MAGIC):
		swapped = true;
	}

	return swapped;
}

static inline u32 pcap_get_length(pcap_pkthdr_t *phdr, enum pcap_type type)
{
	switch (type) {
#define CASE_RET_CAPLEN(what, member, swap, extra) \
	case (what): \
		return (swap ? ___constant_swab32(phdr->member.caplen) : \
		        phdr->member.caplen) - extra

	CASE_RET_CAPLEN(DEFAULT, ppo, 0, 0);
	CASE_RET_CAPLEN(NSEC, ppn, 0, 0);
	CASE_RET_CAPLEN(DEFAULT_LL, ppo_ll, 0, sizeof(struct pcap_ll));
	CASE_RET_CAPLEN(NSEC_LL, ppn_ll, 0, sizeof(struct pcap_ll));
	CASE_RET_CAPLEN(KUZNETZOV, ppk, 0, 0);
	CASE_RET_CAPLEN(BORKMANN, ppb, 0, 0);

	CASE_RET_CAPLEN(DEFAULT_SWAPPED, ppo, 1, 0);
	CASE_RET_CAPLEN(NSEC_SWAPPED, ppn, 1, 0);
	CASE_RET_CAPLEN(DEFAULT_LL_SWAPPED, ppo_ll, 1, sizeof(struct pcap_ll));
	CASE_RET_CAPLEN(NSEC_LL_SWAPPED, ppn_ll, 1, sizeof(struct pcap_ll));
	CASE_RET_CAPLEN(KUZNETZOV_SWAPPED, ppk, 1, 0);
	CASE_RET_CAPLEN(BORKMANN_SWAPPED, ppb, 1, 0);

	default:
		bug();
	}
}

static inline void pcap_set_length(pcap_pkthdr_t *phdr, enum pcap_type type, u32 len)
{
	switch (type) {
#define CASE_SET_CAPLEN(what, member, swap) \
	case (what): \
		phdr->member.caplen = (swap ? ___constant_swab32(len) : len); \
		break

	CASE_SET_CAPLEN(DEFAULT, ppo, 0);
	CASE_SET_CAPLEN(NSEC, ppn, 0);
	CASE_SET_CAPLEN(DEFAULT_LL, ppo_ll, 0);
	CASE_SET_CAPLEN(NSEC_LL, ppn_ll, 0);
	CASE_SET_CAPLEN(KUZNETZOV, ppk, 0);
	CASE_SET_CAPLEN(BORKMANN, ppb, 0);

	CASE_SET_CAPLEN(DEFAULT_SWAPPED, ppo, 1);
	CASE_SET_CAPLEN(NSEC_SWAPPED, ppn, 1);
	CASE_SET_CAPLEN(DEFAULT_LL_SWAPPED, ppo_ll, 1);
	CASE_SET_CAPLEN(NSEC_LL_SWAPPED, ppn_ll, 1);
	CASE_SET_CAPLEN(KUZNETZOV_SWAPPED, ppk, 1);
	CASE_SET_CAPLEN(BORKMANN_SWAPPED, ppb, 1);

	default:
		bug();
	}
}

static inline u32 pcap_get_hdr_length(pcap_pkthdr_t *phdr, enum pcap_type type)
{
	switch (type) {
#define CASE_RET_HDRLEN(what, member) \
	case (what): \
		return sizeof(phdr->member)

	CASE_RET_HDRLEN(DEFAULT, ppo);
	CASE_RET_HDRLEN(NSEC, ppn);
	CASE_RET_HDRLEN(DEFAULT_LL, ppo_ll);
	CASE_RET_HDRLEN(NSEC_LL, ppn_ll);
	CASE_RET_HDRLEN(KUZNETZOV, ppk);
	CASE_RET_HDRLEN(BORKMANN, ppb);

	CASE_RET_HDRLEN(DEFAULT_SWAPPED, ppo);
	CASE_RET_HDRLEN(NSEC_SWAPPED, ppn);
	CASE_RET_HDRLEN(DEFAULT_LL_SWAPPED, ppo_ll);
	CASE_RET_HDRLEN(NSEC_LL_SWAPPED, ppn_ll);
	CASE_RET_HDRLEN(KUZNETZOV_SWAPPED, ppk);
	CASE_RET_HDRLEN(BORKMANN_SWAPPED, ppb);

	default:
		bug();
	}
}

static inline u32 pcap_get_total_length(pcap_pkthdr_t *phdr, enum pcap_type type)
{
	return pcap_get_hdr_length(phdr, type) + pcap_get_length(phdr, type);
}

static inline void
__tpacket_hdr_to_pcap_pkthdr(uint32_t sec, uint32_t nsec, uint32_t snaplen,
			     uint32_t len, uint32_t status,
			     struct sockaddr_ll *sll, pcap_pkthdr_t *phdr,
			     enum pcap_type type)
{
	switch (type) {
	case DEFAULT:
	case DEFAULT_LL:
		phdr->ppo.ts.tv_sec = sec;
		phdr->ppo.ts.tv_usec = nsec / 1000;
		phdr->ppo.caplen = snaplen;
		phdr->ppo.len = len;
		if (type == DEFAULT_LL) {
			phdr->ppo.caplen += sizeof(struct pcap_ll);
			phdr->ppo.len += sizeof(struct pcap_ll);
			sockaddr_to_ll(sll, &phdr->ppo_ll.ll);
		}
		break;

	case DEFAULT_SWAPPED:
	case DEFAULT_LL_SWAPPED:
		phdr->ppo.ts.tv_sec = ___constant_swab32(sec);
		phdr->ppo.ts.tv_usec = ___constant_swab32(nsec / 1000);
		phdr->ppo.caplen = ___constant_swab32(snaplen);
		phdr->ppo.len = ___constant_swab32(len);
		if (type == DEFAULT_LL_SWAPPED) {
			phdr->ppo.caplen = ___constant_swab32(snaplen + sizeof(struct pcap_ll));
			phdr->ppo.len = ___constant_swab32(len + sizeof(struct pcap_ll));
			sockaddr_to_ll(sll, &phdr->ppo_ll.ll);
		}
		break;

	case NSEC:
	case NSEC_LL:
		phdr->ppn.ts.tv_sec = sec;
		phdr->ppn.ts.tv_nsec = nsec;
		phdr->ppn.caplen = snaplen;
		phdr->ppn.len = len;
		if (type == NSEC_LL) {
			phdr->ppn.caplen += sizeof(struct pcap_ll);
			phdr->ppn.len += sizeof(struct pcap_ll);
			sockaddr_to_ll(sll, &phdr->ppn_ll.ll);
		}
		break;

	case NSEC_SWAPPED:
	case NSEC_LL_SWAPPED:
		phdr->ppn.ts.tv_sec = ___constant_swab32(sec);
		phdr->ppn.ts.tv_nsec = ___constant_swab32(nsec);
		phdr->ppn.caplen = ___constant_swab32(snaplen);
		phdr->ppn.len = ___constant_swab32(len);
		if (type == NSEC_LL_SWAPPED) {
			phdr->ppn.caplen = ___constant_swab32(snaplen + sizeof(struct pcap_ll));
			phdr->ppn.len = ___constant_swab32(len + sizeof(struct pcap_ll));
			sockaddr_to_ll(sll, &phdr->ppn_ll.ll);
		}
		break;

	case KUZNETZOV:
		phdr->ppk.ts.tv_sec = sec;
		phdr->ppk.ts.tv_usec = nsec / 1000;
		phdr->ppk.caplen = snaplen;
		phdr->ppk.len = len;
		phdr->ppk.ifindex = sll->sll_ifindex;
		phdr->ppk.protocol = sll->sll_protocol;
		phdr->ppk.pkttype = sll->sll_pkttype;
		break;

	case KUZNETZOV_SWAPPED:
		phdr->ppk.ts.tv_sec = ___constant_swab32(sec);
		phdr->ppk.ts.tv_usec = ___constant_swab32(nsec / 1000);
		phdr->ppk.caplen = ___constant_swab32(snaplen);
		phdr->ppk.len = ___constant_swab32(len);
		phdr->ppk.ifindex = ___constant_swab32(sll->sll_ifindex);
		phdr->ppk.protocol = ___constant_swab16(sll->sll_protocol);
		phdr->ppk.pkttype = sll->sll_pkttype;
		break;

	case BORKMANN:
		phdr->ppb.ts.tv_sec = sec;
		phdr->ppb.ts.tv_nsec = nsec;
		phdr->ppb.caplen = snaplen;
		phdr->ppb.len = len;
		phdr->ppb.tsource = tp_to_pcap_tsource(status);
		phdr->ppb.ifindex = (u16) sll->sll_ifindex;
		phdr->ppb.protocol = sll->sll_protocol;
		phdr->ppb.hatype = sll->sll_hatype;
		phdr->ppb.pkttype = sll->sll_pkttype;
		break;

	case BORKMANN_SWAPPED:
		phdr->ppb.ts.tv_sec = ___constant_swab32(sec);
		phdr->ppb.ts.tv_nsec = ___constant_swab32(nsec);
		phdr->ppb.caplen = ___constant_swab32(snaplen);
		phdr->ppb.len = ___constant_swab32(len);
		phdr->ppb.tsource = ___constant_swab16(tp_to_pcap_tsource(status));
		phdr->ppb.ifindex = ___constant_swab16((u16) sll->sll_ifindex);
		phdr->ppb.protocol = ___constant_swab16(sll->sll_protocol);
		phdr->ppb.hatype = sll->sll_hatype;
		phdr->ppb.pkttype = sll->sll_pkttype;
		break;

	default:
		bug();
	}
}

/* We need to do this crap here since member offsets are not interleaved,
 * so hopfully the compiler does his job here. ;-)
 */

static inline void tpacket_hdr_to_pcap_pkthdr(struct tpacket2_hdr *thdr,
					      struct sockaddr_ll *sll,
					      pcap_pkthdr_t *phdr,
					      enum pcap_type type)
{
	__tpacket_hdr_to_pcap_pkthdr(thdr->tp_sec, thdr->tp_nsec,
				     thdr->tp_snaplen, thdr->tp_len,
				     thdr->tp_status, sll, phdr, type);
}

#ifdef HAVE_TPACKET3
static inline void tpacket3_hdr_to_pcap_pkthdr(struct tpacket3_hdr *thdr,
					       struct sockaddr_ll *sll,
					       pcap_pkthdr_t *phdr,
					       enum pcap_type type)
{
	__tpacket_hdr_to_pcap_pkthdr(thdr->tp_sec, thdr->tp_nsec,
				     thdr->tp_snaplen, thdr->tp_len,
				     0, sll, phdr, type);
}
#endif

static inline void pcap_pkthdr_to_tpacket_hdr(pcap_pkthdr_t *phdr,
					      enum pcap_type type,
					      struct tpacket2_hdr *thdr,
					      struct sockaddr_ll *sll)
{
	switch (type) {
	case DEFAULT:
	case DEFAULT_LL:
		thdr->tp_sec = phdr->ppo.ts.tv_sec;
		thdr->tp_nsec = phdr->ppo.ts.tv_usec * 1000;
		thdr->tp_snaplen = phdr->ppo.caplen;
		thdr->tp_len = phdr->ppo.len;
		if (type == DEFAULT_LL) {
			thdr->tp_snaplen -= sizeof(struct pcap_ll);
			thdr->tp_len -= sizeof(struct pcap_ll);
			if (sll)
				ll_to_sockaddr(&phdr->ppo_ll.ll, sll);
		}
		break;

	case DEFAULT_SWAPPED:
	case DEFAULT_LL_SWAPPED:
		thdr->tp_sec = ___constant_swab32(phdr->ppo.ts.tv_sec);
		thdr->tp_nsec = ___constant_swab32(phdr->ppo.ts.tv_usec) * 1000;
		thdr->tp_snaplen = ___constant_swab32(phdr->ppo.caplen);
		thdr->tp_len = ___constant_swab32(phdr->ppo.len);
		if (type == DEFAULT_LL_SWAPPED) {
			thdr->tp_snaplen -= sizeof(struct pcap_ll);
			thdr->tp_len -= sizeof(struct pcap_ll);
			if (sll)
				ll_to_sockaddr(&phdr->ppo_ll.ll, sll);
		}
		break;

	case NSEC:
	case NSEC_LL:
		thdr->tp_sec = phdr->ppn.ts.tv_sec;
		thdr->tp_nsec = phdr->ppn.ts.tv_nsec;
		thdr->tp_snaplen = phdr->ppn.caplen;
		thdr->tp_len = phdr->ppn.len;
		if (type == NSEC_LL) {
			thdr->tp_snaplen -= sizeof(struct pcap_ll);
			thdr->tp_len -= sizeof(struct pcap_ll);
			if (sll)
				ll_to_sockaddr(&phdr->ppn_ll.ll, sll);
		}
		break;

	case NSEC_SWAPPED:
	case NSEC_LL_SWAPPED:
		thdr->tp_sec = ___constant_swab32(phdr->ppn.ts.tv_sec);
		thdr->tp_nsec = ___constant_swab32(phdr->ppn.ts.tv_nsec);
		thdr->tp_snaplen = ___constant_swab32(phdr->ppn.caplen);
		thdr->tp_len = ___constant_swab32(phdr->ppn.len);
		if (type == NSEC_LL_SWAPPED) {
			thdr->tp_snaplen -= sizeof(struct pcap_ll);
			thdr->tp_len -= sizeof(struct pcap_ll);
			if (sll)
				ll_to_sockaddr(&phdr->ppn_ll.ll, sll);
		}
		break;

	case KUZNETZOV:
		thdr->tp_sec = phdr->ppk.ts.tv_sec;
		thdr->tp_nsec = phdr->ppk.ts.tv_usec * 1000;
		thdr->tp_snaplen = phdr->ppk.caplen;
		thdr->tp_len = phdr->ppk.len;
		if (sll) {
			sll->sll_ifindex = phdr->ppk.ifindex;
			sll->sll_protocol = phdr->ppk.protocol;
			sll->sll_pkttype = phdr->ppk.pkttype;
		}
		break;

	case KUZNETZOV_SWAPPED:
		thdr->tp_sec = ___constant_swab32(phdr->ppk.ts.tv_sec);
		thdr->tp_nsec = ___constant_swab32(phdr->ppk.ts.tv_usec) * 1000;
		thdr->tp_snaplen = ___constant_swab32(phdr->ppk.caplen);
		thdr->tp_len = ___constant_swab32(phdr->ppk.len);
		if (sll) {
			sll->sll_ifindex = ___constant_swab32(phdr->ppk.ifindex);
			sll->sll_protocol = ___constant_swab16(phdr->ppk.protocol);
			sll->sll_pkttype = phdr->ppk.pkttype;
		}
		break;

	case BORKMANN:
		thdr->tp_sec = phdr->ppb.ts.tv_sec;
		thdr->tp_nsec = phdr->ppb.ts.tv_nsec;
		thdr->tp_snaplen = phdr->ppb.caplen;
		thdr->tp_len = phdr->ppb.len;
		if (sll) {
			sll->sll_ifindex = phdr->ppb.ifindex;
			sll->sll_protocol = phdr->ppb.protocol;
			sll->sll_hatype = phdr->ppb.hatype;
			sll->sll_pkttype = phdr->ppb.pkttype;
		}
		break;

	case BORKMANN_SWAPPED:
		thdr->tp_sec = ___constant_swab32(phdr->ppb.ts.tv_sec);
		thdr->tp_nsec = ___constant_swab32(phdr->ppb.ts.tv_nsec);
		thdr->tp_snaplen = ___constant_swab32(phdr->ppb.caplen);
		thdr->tp_len = ___constant_swab32(phdr->ppb.len);
		if (sll) {
			sll->sll_ifindex = ___constant_swab16(phdr->ppb.ifindex);
			sll->sll_protocol = ___constant_swab16(phdr->ppb.protocol);
			sll->sll_hatype = phdr->ppb.hatype;
			sll->sll_pkttype = phdr->ppb.pkttype;
		}
		break;

	default:
		bug();
	}
}

#define FEATURE_UNKNOWN		(0 << 0)
#define FEATURE_TIMEVAL_MS	(1 << 0)
#define FEATURE_TIMEVAL_NS	(1 << 1)
#define FEATURE_LEN		(1 << 2)
#define FEATURE_CAPLEN		(1 << 3)
#define FEATURE_IFINDEX		(1 << 4)
#define FEATURE_PROTO		(1 << 5)
#define FEATURE_HATYPE		(1 << 6)
#define FEATURE_PKTTYPE		(1 << 7)
#define FEATURE_TSOURCE		(1 << 8)

struct pcap_magic_type {
	const uint32_t magic;
	const char *desc;
	const uint16_t features;
};

static const struct pcap_magic_type pcap_magic_types[] __maybe_unused = {
	{
		.magic = ORIGINAL_TCPDUMP_MAGIC,
		.desc = "tcpdump-capable pcap",
		.features = FEATURE_TIMEVAL_MS |
			    FEATURE_LEN |
			    FEATURE_CAPLEN,
	}, {
		.magic = NSEC_TCPDUMP_MAGIC,
		.desc = "tcpdump-capable pcap with ns resolution",
		.features = FEATURE_TIMEVAL_NS |
			    FEATURE_LEN |
			    FEATURE_CAPLEN,
	}, {
		.magic = KUZNETZOV_TCPDUMP_MAGIC,
		.desc = "Alexey Kuznetzov's pcap",
		.features = FEATURE_TIMEVAL_MS |
			    FEATURE_LEN |
			    FEATURE_CAPLEN |
			    FEATURE_IFINDEX |
			    FEATURE_PROTO |
			    FEATURE_PKTTYPE,
	}, {
		.magic = BORKMANN_TCPDUMP_MAGIC,
		.desc = "netsniff-ng pcap",
		.features = FEATURE_TIMEVAL_NS |
			    FEATURE_LEN |
			    FEATURE_CAPLEN |
			    FEATURE_TSOURCE |
			    FEATURE_IFINDEX |
			    FEATURE_PROTO |
			    FEATURE_HATYPE |
			    FEATURE_PKTTYPE,
	},
};

static inline void pcap_dump_type_features(void)
{
	size_t i;

	for (i = 0; i < array_size(pcap_magic_types); ++i) {
		printf("%s:\n", pcap_magic_types[i].desc);
		printf("  magic: 0x%x (swapped: 0x%x)\n",
		       pcap_magic_types[i].magic,
		       ___constant_swab32(pcap_magic_types[i].magic));
		printf("  features:\n");

		if (pcap_magic_types[i].features == FEATURE_UNKNOWN) {
			printf("    unknown\n");
			continue;
		}

		if (pcap_magic_types[i].features & FEATURE_TIMEVAL_MS)
			printf("    timeval in us\n");
		if (pcap_magic_types[i].features & FEATURE_TIMEVAL_NS)
			printf("    timeval in ns\n");
		if (pcap_magic_types[i].features & FEATURE_TSOURCE)
			printf("    timestamp source\n");
		if (pcap_magic_types[i].features & FEATURE_LEN)
			printf("    packet length\n");
		if (pcap_magic_types[i].features & FEATURE_CAPLEN)
			printf("    packet cap-length\n");
		if (pcap_magic_types[i].features & FEATURE_IFINDEX)
			printf("    packet ifindex\n");
		if (pcap_magic_types[i].features & FEATURE_PROTO)
			printf("    packet protocol\n");
		if (pcap_magic_types[i].features & FEATURE_HATYPE)
			printf("    hardware type\n");
		if (pcap_magic_types[i].features & FEATURE_PKTTYPE)
			printf("    packet type\n");
	}
}

static const char *pcap_ops_group_to_str[] __maybe_unused = {
	[PCAP_OPS_RW] = "read/write",
	[PCAP_OPS_SG] = "scatter-gather",
	[PCAP_OPS_MM] = "mmap",
};

static const struct pcap_file_ops *pcap_ops[] __maybe_unused = {
	[PCAP_OPS_RW]		=	&pcap_rw_ops,
	[PCAP_OPS_SG]		=	&pcap_sg_ops,
	[PCAP_OPS_MM]		=	&pcap_mm_ops,
};

static inline void pcap_prepare_header(struct pcap_filehdr *hdr, uint32_t magic,
				       uint32_t linktype, int32_t thiszone,
				       uint32_t snaplen)
{
	bool swapped = pcap_magic_is_swapped(magic);

	/* As *_LL types are just internal, we need to remap pcap
	 * magics to actually valid types.
	 */
	switch (magic) {
	case ORIGINAL_TCPDUMP_MAGIC_LL:
		magic = ORIGINAL_TCPDUMP_MAGIC;
		break;
	case NSEC_TCPDUMP_MAGIC_LL:
		magic = NSEC_TCPDUMP_MAGIC;
		break;
	case ___constant_swab32(ORIGINAL_TCPDUMP_MAGIC_LL):
		magic = ___constant_swab32(ORIGINAL_TCPDUMP_MAGIC);
		break;
	case ___constant_swab32(NSEC_TCPDUMP_MAGIC_LL):
		magic = ___constant_swab32(NSEC_TCPDUMP_MAGIC);
		break;
	}

	hdr->magic = magic;
	hdr->version_major = swapped ? ___constant_swab16(PCAP_VERSION_MAJOR) : PCAP_VERSION_MAJOR;
	hdr->version_minor = swapped ? ___constant_swab16(PCAP_VERSION_MINOR) : PCAP_VERSION_MINOR;
	hdr->thiszone = swapped ? (int32_t) ___constant_swab32(thiszone)  : thiszone;
	hdr->sigfigs = 0;
	hdr->snaplen = swapped ? ___constant_swab32(snaplen) : snaplen;
	hdr->linktype = swapped ? ___constant_swab32(linktype) : linktype;
}

static const bool pcap_supported_linktypes[LINKTYPE_MAX] __maybe_unused = {
	/* tunX captures from wireshark/tcpdump, non-portable */
	[101] = true, [102] = true, [103] = true,
	[LINKTYPE_NULL] = true,
	[LINKTYPE_EN10MB] = true,
	[LINKTYPE_EN3MB] = true,
	[LINKTYPE_AX25] = true,
	[LINKTYPE_PRONET] = true,
	[LINKTYPE_CHAOS] = true,
	[LINKTYPE_IEEE802] = true,
	[LINKTYPE_SLIP] = true,
	[LINKTYPE_PPP] = true,
	[LINKTYPE_FDDI] = true,
	[LINKTYPE_ATM_CLIP] = true,
	[LINKTYPE_C_HDLC] = true,
	[LINKTYPE_IEEE802_11] = true,
	[LINKTYPE_IEEE802_11_RADIOTAP] = true,
	[LINKTYPE_FRELAY] = true,
	[LINKTYPE_ECONET] = true,
	[LINKTYPE_ARCNET_LINUX] = true,
	[LINKTYPE_LINUX_IRDA] = true,
	[LINKTYPE_CAN20B] = true,
	[LINKTYPE_IEEE802_15_4_LINUX] = true,
	[LINKTYPE_INFINIBAND] = true,
	[LINKTYPE_NETLINK] = true,
	[LINKTYPE_LINUX_SLL] = true,
};

static inline void pcap_validate_header(struct pcap_filehdr *hdr)
{
	bool good = false;
	uint32_t linktype;

	pcap_check_magic(hdr->magic);

	linktype = pcap_magic_is_swapped(hdr->magic) ? bswap_32(hdr->linktype) : hdr->linktype;
	if (linktype < LINKTYPE_MAX)
		good = pcap_supported_linktypes[linktype];

	if (!good)
		panic("This file has an unsupported pcap link type (%d)!\n", linktype);
	if (unlikely(hdr->version_major != PCAP_VERSION_MAJOR) &&
		     ___constant_swab16(hdr->version_major) != PCAP_VERSION_MAJOR)
		panic("This file has an invalid pcap major version (must be %d)\n", PCAP_VERSION_MAJOR);
	if (unlikely(hdr->version_minor != PCAP_VERSION_MINOR) &&
		     ___constant_swab16(hdr->version_minor) != PCAP_VERSION_MINOR)
		panic("This file has an invalid pcap minor version (must be %d)\n", PCAP_VERSION_MINOR);

	/* Remap to internal *_LL types in case of LINKTYPE_LINUX_SLL. */
	if (linktype == LINKTYPE_LINUX_SLL || linktype == LINKTYPE_NETLINK) {
		switch (hdr->magic) {
		case ORIGINAL_TCPDUMP_MAGIC:
			hdr->magic = ORIGINAL_TCPDUMP_MAGIC_LL;
			break;
		case NSEC_TCPDUMP_MAGIC:
			hdr->magic = NSEC_TCPDUMP_MAGIC_LL;
			break;
		case ___constant_swab32(ORIGINAL_TCPDUMP_MAGIC):
			hdr->magic = ___constant_swab32(ORIGINAL_TCPDUMP_MAGIC_LL);
			break;
		case ___constant_swab32(NSEC_TCPDUMP_MAGIC):
			hdr->magic = ___constant_swab32(NSEC_TCPDUMP_MAGIC_LL);
			break;
		}
	}
}

static int pcap_generic_pull_fhdr(int fd, uint32_t *magic,
				  uint32_t *linktype) __maybe_unused;

static int pcap_generic_pull_fhdr(int fd, uint32_t *magic, uint32_t *linktype)
{
	ssize_t ret;
	struct pcap_filehdr hdr;

	ret = read(fd, &hdr, sizeof(hdr));
	if (unlikely(ret != sizeof(hdr)))
		return -EIO;

	pcap_validate_header(&hdr);

	*magic = hdr.magic;
	*linktype = hdr.linktype;

	return 0;
}

static int pcap_generic_push_fhdr(int fd, uint32_t magic,
				  uint32_t linktype) __maybe_unused;

static int pcap_generic_push_fhdr(int fd, uint32_t magic, uint32_t linktype)
{
	ssize_t ret;
	struct pcap_filehdr hdr;

	memset(&hdr, 0, sizeof(hdr));

	pcap_prepare_header(&hdr, magic, linktype, 0, PCAP_DEFAULT_SNAPSHOT_LEN);

	ret = write_or_die(fd, &hdr, sizeof(hdr));
	if (unlikely(ret != sizeof(hdr)))
		panic("Failed to write pkt file header!\n");

	return 0;
}

extern void pcap_io_init(struct pcap_io *io, enum pcap_ops_groups ops_type);
extern void pcap_io_open(struct pcap_io *io, const char *path, enum pcap_mode mode);
extern void pcap_io_header_copy(struct pcap_io *to, struct pcap_io *from);
extern int pcap_io_header_read(struct pcap_io *io);
extern int pcap_io_header_write(struct pcap_io *io);
extern int pcap_io_packet_read(struct pcap_io *io, struct pcap_packet *pk);
extern int pcap_io_packet_write(struct pcap_io *io, struct pcap_packet *pkt);
extern void pcap_io_close(struct pcap_io *io);

extern struct pcap_packet *pcap_packet_alloc(struct pcap_io *io);
extern void pcap_packet_free(struct pcap_packet *pkt);
extern void pcap_packet_buf_alloc(struct pcap_packet *pkt, uint32_t len);

static inline uint32_t pcap_packet_len_get(struct pcap_packet *pkt)
{
	return pcap_get_length(&pkt->phdr, pkt->io->magic);
}

static inline void pcap_packet_len_set(struct pcap_packet *pkt, uint32_t len)
{
	pcap_set_length(&pkt->phdr, pkt->io->magic, len);
}

static inline uint32_t pcap_io_pcap_type_get(struct pcap_io *io)
{
	return io->magic;
}

static inline void pcap_io_pcap_type_set(struct pcap_io *io, uint32_t type)
{
	io->magic = type;
}

static inline uint32_t pcap_io_link_type_get(struct pcap_io *io)
{
	return io->link_type;
}

static inline void pcap_io_link_type_set(struct pcap_io *io, uint32_t link_type)
{
	io->link_type = link_type;
}

static inline void pcap_io_enforce_prio_set(struct pcap_io *io, bool enforce)
{
	io->enforce_prio = enforce;
}

static inline void pcap_io_jumbo_enable_set(struct pcap_io *io, bool jumbo)
{
	io->jumbo = jumbo;
}

static inline void pcap_io_bpf_apply(struct pcap_io *io, struct sock_fprog *bpf)
{
	io->bpf_ops = bpf;
}

static inline uint64_t pcap_io_truncated_get(struct pcap_io *io)
{
	return io->truncated;
}

static inline void pcap_packet_buf_set(struct pcap_packet *pkt, uint8_t *buf)
{
	pkt->buf = buf;
}

static inline uint8_t *pcap_packet_buf_get(struct pcap_packet *pkt)
{
	return pkt->buf;
}

static inline void pcap_packet_buf_len_set(struct pcap_packet *pkt, uint32_t len)
{
	pkt->buf_len = len;
}

static inline uint32_t pcap_packet_buf_len_get(struct pcap_packet *pkt)
{
	return pkt->buf_len;
}

static inline uint8_t *pcap_packet_payload_get(struct pcap_packet *pkt)
{
	return pkt->buf;
}

static inline pcap_pkthdr_t *pcap_packet_header_get(struct pcap_packet *pkt)
{
	return &pkt->phdr;
}

static inline void pcap_packet_to_tpacket2(struct pcap_packet *pkt,
					   struct tpacket2_hdr *thdr,
					   struct sockaddr_ll *sll)
{
	pcap_pkthdr_to_tpacket_hdr(&pkt->phdr, pkt->io->magic, thdr, sll);
}

static inline void pcap_packet_from_tpacket2(struct pcap_packet *pkt,
					     struct tpacket2_hdr *thdr,
					     struct sockaddr_ll *sll)
{
	tpacket_hdr_to_pcap_pkthdr(thdr, sll, &pkt->phdr, pkt->io->magic);
}

#ifdef HAVE_TPACKET3
static inline void pcap_packet_from_tpacket3(struct pcap_packet *pkt,
					     struct tpacket3_hdr *thdr,
					     struct sockaddr_ll *sll)

{
	tpacket3_hdr_to_pcap_pkthdr(thdr, sll, &pkt->phdr, pkt->io->magic);
}
#endif

#endif /* PCAP_IO_H */
