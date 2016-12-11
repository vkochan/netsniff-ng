/*
 * netsniff-ng - the packet sniffing beast
 * Subject to the GPL, version 2.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <sys/stat.h>

#include "bpf.h"
#include "pcap_io.h"
#include "xmalloc.h"

void pcap_io_init(struct pcap_io *io, enum pcap_ops_groups ops_type)
{
	io->ops = pcap_ops[ops_type];
	io->ops_type = ops_type;
	io->bpf_ops = NULL;
	io->jumbo = false;
	io->truncated = 0;
	io->path = NULL;
	io->fd = -1;
	
	bug_on(!io->ops);
}

void pcap_io_open(struct pcap_io *io, const char *path, enum pcap_mode mode)
{
	if (mode == PCAP_MODE_RD) {
		if (!strncmp("-", path, strlen("-"))) {
			io->fd = dup_or_die(fileno(stdin));
			close(fileno(stdin));

			if (io->ops_type == PCAP_OPS_MM)
				pcap_io_init(io, PCAP_OPS_SG);
		} else {
			io->fd = open(path, O_RDONLY | O_LARGEFILE | O_NOATIME);
			if (io->fd < 0 && errno == EPERM)
				io->fd = open_or_die(path, O_RDONLY | O_LARGEFILE);
		}
	} else if (mode == PCAP_MODE_WR) {
		if (!strncmp("-", path, strlen("-"))) {
			io->fd = dup_or_die(fileno(stdout));
			close(fileno(stdout));

			if (io->ops_type == PCAP_OPS_MM)
				pcap_io_init(io, PCAP_OPS_SG);
		} else {
			io->fd = open_or_die_m(path, O_RDWR | O_CREAT | O_TRUNC |
					       O_LARGEFILE, DEFFILEMODE);
		}
	} else {
		bug();
	}

	if (io->fd < 0)
		panic("pcap_io: Cannot open file %s! %s.\n", path, strerror(errno));

	if (io->ops->init_once_pcap)
		io->ops->init_once_pcap(io->enforce_prio);

	io->path = path;
	io->mode = mode;
}

static int pcap_io_prepare_access(struct pcap_io *io)
{
	int ret;

	if (io->ops->prepare_access_pcap) {
		ret = io->ops->prepare_access_pcap(io->fd, io->mode, io->jumbo);
		if (ret) {
			fprintf(stderr, "pcap_io: Error prepare %s pcap!\n",
				io->mode == PCAP_MODE_RD ? "reading" : "writing");

			return ret;
		}
	}

	return 0;
}

void pcap_io_header_copy(struct pcap_io *to, struct pcap_io *from)
{
	to->link_type = from->link_type;
	to->magic     = from->magic;
}

int pcap_io_header_read(struct pcap_io *io)
{
	int ret;

	ret = io->ops->pull_fhdr_pcap(io->fd, &io->magic, &io->link_type);
	if (ret) {
		fprintf(stderr, "pcap_io: Error reading pcap header!\n");
		return ret;
	}

	return pcap_io_prepare_access(io);
}

int pcap_io_header_write(struct pcap_io *io)
{
	int ret;

	ret = io->ops->push_fhdr_pcap(io->fd, io->magic, io->link_type);
	if (ret) {
		fprintf(stderr, "pcap_io: Error writing pcap header!\n");
		return ret;
	}

	return pcap_io_prepare_access(io);
}

int pcap_io_packet_read(struct pcap_io *io, struct pcap_packet *pkt)
{
	int ret;

	do {
		ret = io->ops->read_pcap(io->fd, &pkt->phdr, io->magic,
					 pkt->buf, pkt->buf_len);
		if (unlikely(ret < 0)) {
			return 0;
		}
		if (unlikely(pcap_packet_len_get(pkt) == 0)) {
			pkt->io->truncated++;
			continue;
		}
		if (unlikely(pcap_packet_len_get(pkt) > pkt->buf_len)) {
			pcap_packet_len_set(pkt, pkt->buf_len);
			pkt->io->truncated++;
		}
	} while (io->bpf_ops &&
			!bpf_run_filter(io->bpf_ops, pkt->buf,
					 pcap_packet_len_get(pkt)));

	return ret;
}

int pcap_io_packet_write(struct pcap_io *io, struct pcap_packet *pkt)
{
	size_t pcap_len = pcap_get_length(&pkt->phdr, io->magic);
	uint32_t len = io->ops->write_pcap(io->fd, &pkt->phdr, io->magic,
					   pkt->buf, pcap_len);

	if (unlikely(len != pcap_get_total_length(&pkt->phdr, io->magic)))
		return -1;

	return 0;
}

void pcap_io_close(struct pcap_io *io)
{
	if (io->fd >= 0) {
		if (io->mode == PCAP_MODE_WR)
			io->ops->fsync_pcap(io->fd);

		if (io->ops->prepare_close_pcap)
			io->ops->prepare_close_pcap(io->fd, io->mode);

		if (!strncmp("-", io->path, strlen("-")))
			dup2(io->fd, fileno(stdin));

	}
}

struct pcap_packet *pcap_packet_alloc(struct pcap_io *io)
{
	struct pcap_packet *pkt = xzmalloc(sizeof(*io));

	pkt->io = io;
	return pkt;
}

void pcap_packet_free(struct pcap_packet *pkt)
{
	if (pkt->is_buf_alloc)
		xfree(pkt->buf);

	xfree(pkt);
}

void pcap_packet_buf_alloc(struct pcap_packet *pkt, uint32_t len)
{
	pkt->buf = xmalloc_aligned(len, CO_CACHE_LINE_SIZE);
	pkt->buf_len = len;

	pkt->is_buf_alloc = true;
}
