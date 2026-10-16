/*
	stun.c - minimal RFC 5389 STUN Binding Request/Response responder

	CVars:
	  stun_enable          - 0=off (default), 1=on. Off by default: this
	                         is an opt-in feature, existing deployments
	                         are unaffected until the operator enables it.
	  stun_rate_per_ip     - max STUN responses/sec to a single source IP
	                         (default 10)
	  stun_rate_global     - max STUN responses/sec across all source IPs
	                         combined (default 500)

	Why this exists: a browser cannot open a raw UDP socket, so it can
	never measure real RTT to a qwfwd proxy directly (the QW protocol is
	UDP-only). RTCPeerConnection's ICE candidate gathering, however,
	already knows how to time round-trips to a STUN server as part of
	standard WebRTC NAT traversal - so making this proxy answer STUN
	Binding Requests on its existing UDP port gives the browser a real,
	unspoofable RTT measurement, "for free" the moment an operator
	updates their qwfwd binary and flips stun_enable - no per-proxy
	HTTPS certificate, no separate service, no config beyond one cvar.

	Security posture (why this is safe to expose, briefly - see the
	mesh-routing branch's design notes for the full writeup):
	  - Amplification factor is 1.60x payload / 1.25x with IP+UDP
	    overhead (20-byte request -> fixed 32-byte response). This is far
	    below what's considered a volumetric DoS vector (DNS ~28-54x,
	    NTP ~557x) - STUN is not a useful reflection amplifier.
	  - Still a UDP reflector in principle (spoofed source IP redirects a
	    small reply elsewhere), so this responder is opt-in and rate
	    limited per-IP and globally, on top of whatever perimeter
	    filtering the operator already runs.
	  - No cookie/nonce challenge is possible here (unlike the mesh
	    protocol's meshprobe nonce) - RTCPeerConnection sends anonymous,
	    unauthenticated Binding Requests per the STUN/ICE standard, so
	    requiring a prior handshake would break compatibility with every
	    browser's WebRTC stack.
	  - Every malformed/invalid packet is dropped silently: no per-packet
	    logging (avoids a log-flooding DoS vector), no error reply.
	  - This responder implements ONLY the minimal Binding transaction.
	    No SOFTWARE attribute, no RFC 5780 (NAT behavior discovery), no
	    TURN relay support - nothing beyond what "measure my RTT to this
	    address" requires.
*/
#include "qwfwd.h"
#include "stun.h"

static cvar_t *stun_enable;
static cvar_t *stun_rate_per_ip;
static cvar_t *stun_rate_global;

// --------------------------------------------
// STUN wire constants (RFC 5389)
// --------------------------------------------
#define STUN_HEADER_SIZE          20
#define STUN_MAX_PACKET_SIZE      512   // generous ceiling; our own requests/replies are tiny
#define STUN_MAGIC_COOKIE         0x2112A442u
#define STUN_TYPE_BINDING_REQUEST 0x0001
#define STUN_TYPE_BINDING_SUCCESS 0x0101
#define STUN_ATTR_XOR_MAPPED_ADDR 0x0020
#define STUN_FAMILY_IPV4          0x01

// --------------------------------------------
// Rate limiting - deliberately separate from the mesh protocol's
// existing nonce table (query.c): that table is small (64 slots) and
// sized for mesh peer counts, not for an open, anonymous, internet-facing
// responder. Keyed by source IP only (not IP:port - a spoofing/rotation
// attacker changing source port trivially would otherwise bypass a
// per-socket limit for free).
// --------------------------------------------
#define STUN_RATE_BUCKETS 4096

typedef struct stun_rate_bucket_s
{
	unsigned int ip;          // 0 == empty slot
	double       window_start;
	int          count_in_window;
} stun_rate_bucket_t;

static stun_rate_bucket_t stun_rate_table[STUN_RATE_BUCKETS];
static double             stun_global_window_start = 0;
static int                stun_global_count_in_window = 0;

static unsigned int stun_hash_ip(unsigned int ip)
{
	// simple multiplicative hash, table size is a power of two
	return (ip * 2654435761u) & (STUN_RATE_BUCKETS - 1);
}

// Returns true if this source IP (and the global budget) still has rate
// budget this second, and consumes one unit of budget if so. Uses a
// fixed one-second sliding window per bucket/global counter (not a token
// bucket) - simple, O(1), good enough for a "don't be a useful reflector"
// guard rather than precise traffic shaping.
static qbool STUN_RateLimitAllow(unsigned int ip)
{
	double now = Sys_DoubleTime();
	unsigned int h = stun_hash_ip(ip);
	stun_rate_bucket_t *b = &stun_rate_table[h];
	int per_ip_limit = stun_rate_per_ip->integer > 0 ? stun_rate_per_ip->integer : 10;
	int global_limit = stun_rate_global->integer > 0 ? stun_rate_global->integer : 500;

	// global budget first (cheap, protects CPU/socket regardless of
	// which IPs are involved)
	if (now - stun_global_window_start >= 1.0)
	{
		stun_global_window_start = now;
		stun_global_count_in_window = 0;
	}
	if (stun_global_count_in_window >= global_limit)
		return false;

	// per-IP bucket. A hash collision between two different IPs just
	// makes them share a budget slightly early under load - acceptable
	// for a DoS guard, not a correctness-critical structure.
	if (b->ip != ip || now - b->window_start >= 1.0)
	{
		b->ip = ip;
		b->window_start = now;
		b->count_in_window = 0;
	}
	if (b->count_in_window >= per_ip_limit)
		return false;

	b->count_in_window++;
	stun_global_count_in_window++;
	return true;
}

// --------------------------------------------
// Wire helpers - STUN header/attribute fields are all big-endian, unlike
// the rest of this codebase's little-endian QW protocol (MSG_ReadLong
// etc are the wrong tool here: different byte order, different framing).
// --------------------------------------------
static unsigned int ReadU32BE(const byte *p)
{
	return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
	       ((unsigned int)p[2] << 8)  |  (unsigned int)p[3];
}

static unsigned short ReadU16BE(const byte *p)
{
	return (unsigned short)(((unsigned int)p[0] << 8) | (unsigned int)p[1]);
}

static void WriteU32BE(byte *p, unsigned int v)
{
	p[0] = (byte)(v >> 24); p[1] = (byte)(v >> 16);
	p[2] = (byte)(v >> 8);  p[3] = (byte)v;
}

static void WriteU16BE(byte *p, unsigned short v)
{
	p[0] = (byte)(v >> 8); p[1] = (byte)v;
}

// --------------------------------------------
// PUBLIC: STUN_HandlePacket
// --------------------------------------------
qbool STUN_HandlePacket(const byte *data, int len, struct sockaddr_in *from)
{
	byte   response[32];   // header(20) + XOR-MAPPED-ADDRESS attribute(12) = 32 bytes, fixed
	unsigned int msg_len;
	unsigned int cookie;
	unsigned int src_ip;
	byte   addr_bytes[4]; // from->sin_addr.s_addr's 4 bytes, in on-the-wire order
	byte   port_bytes[2]; // from->sin_port's 2 bytes, in on-the-wire order

	if (!stun_enable || !stun_enable->integer)
		return false; // feature disabled - let the caller fall through to normal handling

	// A STUN message's first two bits are always 0b00 (this is how STUN
	// coexists on the same port as other UDP protocols per RFC 5389
	// sec 6). Everything else here is bounds/format validation - any
	// failure means "not a valid STUN Binding Request", drop silently,
	// never log per-packet (a flood of garbage must not become a log-DoS).
	if (len < STUN_HEADER_SIZE || len > STUN_MAX_PACKET_SIZE)
		return false;

	if ((data[0] & 0xC0) != 0x00)
		return false; // not STUN - top 2 bits must be zero

	if (ReadU16BE(data) != STUN_TYPE_BINDING_REQUEST)
		return false; // only handle Binding Request, nothing else

	msg_len = ReadU16BE(data + 2);
	if ((msg_len & 3) != 0)
		return false; // STUN attribute section is always a multiple of 4 bytes
	if ((unsigned int)(STUN_HEADER_SIZE + msg_len) != (unsigned int)len)
		return false; // declared length must exactly match the datagram we received

	cookie = ReadU32BE(data + 4);
	if (cookie != STUN_MAGIC_COOKIE)
		return false; // not a STUN message we recognize (RFC 3489 legacy has no cookie - not supported)

	// Passed all format checks - this is a real STUN Binding Request.
	// Apply rate limiting before doing any more work or sending a reply.
	src_ip = (unsigned int)from->sin_addr.s_addr; // network byte order, used only as an opaque hash key, never arithmetic
	if (!STUN_RateLimitAllow(src_ip))
		return true; // recognized as STUN, but rate-limited: consume it silently, no reply, no fallthrough to Quake parsing

	// Build the Binding Success Response: same transaction ID (12 bytes
	// at offset 8), one XOR-MAPPED-ADDRESS attribute carrying the
	// requester's own observed address - exactly what ICE gathering
	// needs and nothing more.
	WriteU16BE(response, STUN_TYPE_BINDING_SUCCESS);
	WriteU16BE(response + 2, 12); // attribute section length: 12 bytes (one XOR-MAPPED-ADDRESS attr)
	WriteU32BE(response + 4, STUN_MAGIC_COOKIE);
	memcpy(response + 8, data + 8, 12); // echo transaction ID verbatim

	// sin_port/sin_addr.s_addr are already network byte order (big-endian)
	// in this codebase (see net.c's use of htons/inet_addr) - copy their
	// raw bytes out and XOR byte-by-byte against the cookie/response
	// header's own on-the-wire bytes. Doing this as a byte array instead
	// of an integer XOR sidesteps any dependency on the build machine's
	// native endianness (x86 is little-endian, but nothing here should
	// assume that): every operand here is treated purely as a byte
	// string, matching how the two values are actually laid out on the
	// wire per RFC 5389 sec 15.2, not as numbers.
	memcpy(port_bytes, &from->sin_port, 2);
	memcpy(addr_bytes, &from->sin_addr.s_addr, 4);

	WriteU16BE(response + 20, STUN_ATTR_XOR_MAPPED_ADDR);
	WriteU16BE(response + 22, 8); // attribute value length: family(1)+reserved(1)+port(2)+addr(4) = 8
	response[24] = 0x00;
	response[25] = STUN_FAMILY_IPV4;
	// XOR-port = port XOR (top 16 bits of magic cookie, as it appears in
	// the response header we just wrote at offset 4-5).
	response[26] = (byte)(port_bytes[0] ^ response[4]);
	response[27] = (byte)(port_bytes[1] ^ response[5]);
	// XOR-address = address XOR the full magic cookie (response bytes 4-7).
	response[28] = (byte)(addr_bytes[0] ^ response[4]);
	response[29] = (byte)(addr_bytes[1] ^ response[5]);
	response[30] = (byte)(addr_bytes[2] ^ response[6]);
	response[31] = (byte)(addr_bytes[3] ^ response[7]);

	NET_SendPacket(net_socket, sizeof(response), response, from);

	return true;
}

void STUN_Init(void)
{
	stun_enable      = Cvar_Get("stun_enable",      "0",   0);
	stun_rate_per_ip = Cvar_Get("stun_rate_per_ip", "10",  0);
	stun_rate_global = Cvar_Get("stun_rate_global", "500", 0);

	memset(stun_rate_table, 0, sizeof(stun_rate_table));
}
