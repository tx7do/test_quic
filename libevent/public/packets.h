#pragma once

#include "config.h"

struct read_iter
{
	unsigned ri_idx;    /* Current element */
	unsigned ri_off;    /* Offset into packet_data */
};

enum rop
{
	ROP_OK, ROP_NOROOM, ROP_ERROR,
};

struct packets_in
{
	unsigned char* packet_data;
	unsigned char* ctlmsg_data;
	struct iovec* vecs;
	int* ecn;
	struct sockaddr_storage* local_addresses;
	struct sockaddr_storage* peer_addresses;
	unsigned n_alloc;
	unsigned data_sz;
};

static struct packets_in*
allocate_packets_in(SOCKET_TYPE fd)
{
	struct packets_in* packs_in;
	unsigned n_alloc;
	socklen_t opt_len;
	int recvsz;

	opt_len = sizeof(recvsz);
	if (0 != getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void*)&recvsz, &opt_len))
	{
		return nullptr;
	}

	n_alloc = (unsigned)recvsz / 1370;
	recvsz += MAX_PACKET_SZ;

	packs_in = (packets_in*)malloc(sizeof(*packs_in));
	packs_in->data_sz = recvsz;
	packs_in->n_alloc = n_alloc;
	packs_in->packet_data = (unsigned char*)malloc(recvsz);
	packs_in->ctlmsg_data = (unsigned char*)malloc(n_alloc * CTL_SZ);
	packs_in->vecs = (iovec*)malloc(n_alloc * sizeof(packs_in->vecs[0]));
	packs_in->local_addresses = (sockaddr_storage*)malloc(n_alloc * sizeof(packs_in->local_addresses[0]));
	packs_in->peer_addresses = (sockaddr_storage*)malloc(n_alloc * sizeof(packs_in->peer_addresses[0]));
	packs_in->ecn = (int*)malloc(n_alloc * sizeof(packs_in->ecn[0]));

	return packs_in;
}

static void free_packets_in(struct packets_in* packs_in)
{
	free(packs_in->ecn);
	free(packs_in->peer_addresses);
	free(packs_in->local_addresses);
	free(packs_in->ctlmsg_data);
	free(packs_in->vecs);
	free(packs_in->packet_data);
	free(packs_in);
}
