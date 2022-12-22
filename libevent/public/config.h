#pragma once

#define HAVE_SENDMMSG 1
#define HAVE_RECVMMSG 1
#define HAVE_OPEN_MEMSTREAM 1
#define HAVE_IP_DONTFRAG 1
#define HAVE_IP_MTU_DISCOVER 1
#define HAVE_REGEX 1
#define HAVE_PREADV 1

#define LSQUIC_DONTFRAG_SUPPORTED (HAVE_IP_DONTFRAG || HAVE_IP_MTU_DISCOVER || HAVE_IPV6_MTU_DISCOVER)

/* TODO: presumably it's the same on FreeBSD, test it.
 * See https://github.com/quicwg/base-drafts/wiki/ECN-in-QUIC
 */
#if __linux__ || defined(__FreeBSD__)
#	define ECN_SUPPORTED 1
#else
#	define ECN_SUPPORTED 0
#endif

#define SOCKOPT_VAL int
#define SOCKET_TYPE int

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define MAX_PACKET_SZ 0xffff

#define NDROPPED_SZ CMSG_SPACE(sizeof(uint32_t))  /* SO_RXQ_OVFL */

#define DST_MSG_SZ sizeof(struct in_pktinfo)

#define ECN_SZ CMSG_SPACE(sizeof(int))

#define CTL_SZ (CMSG_SPACE(MAX(DST_MSG_SZ, \
                        sizeof(struct in6_pktinfo))) + NDROPPED_SZ + ECN_SZ)

enum sport_flags : std::int32_t
{
	SPORT_FRAGMENT_OK = (1 << 0),
	SPORT_SET_SNDBUF = (1 << 1), /* SO_SNDBUF */
	SPORT_SET_RCVBUF = (1 << 2), /* SO_RCVBUF */
	SPORT_SERVER = (1 << 3),
	SPORT_CONNECT = (1 << 4),
};
