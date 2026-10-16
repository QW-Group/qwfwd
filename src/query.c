/*
	query.c - query master/normal qw servers
*/

#include "qwfwd.h"
#include <limits.h>

#define QW_SERVER_RATE (0.1) // seconds, accept fraction, how frequently sent ONE packet to some server, so 0.1 means one packet per 1/10 of second
#define QW_SERVER_PING_QUERY "\xff\xff\xff\xffk\n"
#define QW_SERVER_MIN_PING_REQUEST_TIME 60 // seconds, minimal time interval allowed to sent ping, so we do not spam server too fast
#define QW_SERVER_DEAD_TIME (60 * 60) // seconds, if we do not get reply from server in this time, guess server is DEAD


#define QW_MASTER_QUERY "c\n"
#define QW_MASTER_QUERY_TIME (60 * 30) // seconds, how frequently we query masters
#define QW_MASTER_QUERY_TIME_SHORT 60 // seconds, how frequently we query master if we do not get reply from it yet
#define QW_MASTERS_FORCE_RE_INIT (60 * 60 * 24) // seconds, force re-init masters time to time, so we add proper masters if there was some ip/dns changes
#define QW_MASTER_HEARTBEAT_SECONDS (60 * 5) // seconds, frequency of heartbeat

#define QW_DEFAULT_MASTER_SERVERS "master.quakeworld.nu qwmaster.fodquake.net master.quakeservers.net"
#define QW_DEFAULT_MASTER_SERVER_PORT 27000

#define MAX_MASTERS 8 // size for masters fixed size array, I am lazy

#define MAX_SERVERS 1024 // we will not add more than that servers to our list, just for some sanity

#define PING_QUALITY_WINDOW 8 // samples kept per server to compute avg/jitter/loss (accumulated over natural ping cadence, no extra traffic)

#define MAX_SV_FILTERS 16 // how much servers we can filter with masters_filter_servers, can be increased widely.
#define QW_DEFAULT_SV_FILTER "127.0.0.1" // some masters provide unusable servers, filter them.

static cvar_t *masters_query;
static cvar_t *masters_heartbeat;
static cvar_t *masters_list;
static cvar_t *masters_filter_servers;

static cvar_t *mesh_enable;
static cvar_t *mesh_query_interval;	// seconds between re-probes of a confirmed mesh peer
static cvar_t *mesh_probe_interval;	// seconds between (re)probe attempts of an unclassified server

// "meshprobe" is a dedicated query, separate from "pingstatus", so the
// existing pingstatus wire format (consumed today by ezquake's ping tree,
// EX_browser_pathfind.c) never changes shape. Only a qwfwd that understands
// mesh will ever reply to this command.
#define MESH_PROBE_CMD "meshprobe"
#define MESH_PENDING_TIMEOUT 5.0	// seconds - drop an outstanding probe if no reply

// master state enum
typedef enum
{
	ms_unknown,		// unknown state
	ms_used			// this slot used in masters_t struct
} master_state_t;

// single master struct
typedef struct master
{
	master_state_t			state;		// master state
	time_t					next_query;	// next time when query master server
	struct sockaddr_in		addr;		// master addr
} master_t;

// all masters in one struct
typedef struct masters
{
	time_t					init_time;				// this is used to periodical re-init initiation

	time_t					last_heartbeat;			// when we send heartbeat last time
	int						heartbeat_sequence;		// heartbeat sequence number

	master_t				master[MAX_MASTERS];	// masters fixed size array, I am lazy
} masters_t;

// single server struct
typedef struct server
{
	struct sockaddr_in		addr;			// addr

	qbool					reply;			// true if we get reply after ping packet was sent,
											// reset to false each time we sent packet
	double					ping_sent_at;	// last time when we send ping request, so we can calculate ping time
	double					ping_reply_at;	// last time when we receive ping reply from server,
											// so we can guess is server dead etc
	int						ping;			// ping to that server in milliseconds (most recent sample, kept for backward compat with existing pingstatus consumers)

	// quality window: last PING_QUALITY_WINDOW attempts (success = rtt in ms,
	// failure = -1), circular buffer, accumulated over the natural ping
	// cadence (no extra probe traffic). Used to derive avg/jitter/loss.
	short					ping_samples[PING_QUALITY_WINDOW];
	int						ping_samples_count;	// how many slots are filled so far (caps at PING_QUALITY_WINDOW)
	int						ping_samples_next;		// next slot to write (wraps around)

	// mesh (P2P discovery between qwfwd instances) state
	qbool					mesh_probed;		// we've sent at least one pingstatus probe
	qbool					is_mesh;			// confirmed qwfwd: replied with a valid mesh reply
	double					mesh_probe_sent_at;	// last time we sent a probe to this server
	double					mesh_reply_at;		// last time we got a confirmed mesh reply
	unsigned int			mesh_nonce;			// nonce of the currently outstanding probe, 0 = none

	hop2_entry_t			*hop2;			// dynamically allocated, NULL if not a mesh peer
	int						hop2_count;
	int						hop2_capacity;	// allocated capacity (capacity doubling, not per-entry realloc)

	struct server			*next;			// next server in linked list
} server_t;

// explicit byte copy of a raw IPv4 address into a machine int for
// MSG_WriteLong - avoids the strict-aliasing UB of casting a
// struct in_addr* to int* (the original SVC_QRY_PingStatus code does this
// cast; new mesh code uses this helper instead of repeating the hazard)
static int QRY_IPv4AsInt(const struct in_addr *addr)
{
	int value;
	memcpy(&value, addr, sizeof(value));
	return value;
}

// single server_filter struct.
// used by masters_filter_servers.
typedef struct server_filter
{
	struct sockaddr_in		addr[MAX_SV_FILTERS];			// addr[]
	int						count;
} server_filter_t;

static int sv_count;
static server_t *servers;
static server_filter_t server_filter;
static masters_t masters;

static master_t	*QRY_Master_ByAddr(struct sockaddr_in *addr)
{
	int						i;
	master_t				*m;

	for (i = 0, m = masters.master; i < MAX_MASTERS; i++, m++)
	{
		if (m->state != ms_used)
			continue; // master slot unused

		if (NET_CompareAddress(addr, &m->addr))
			return m;
	}

	return NULL;
}

static qbool QRY_AddMaster(const char *master)
{
	int						i, port;
	master_t				*m;
	struct sockaddr_in		addr;
	char					host[1024], *column;

	// decide host:port, port is optional and DEFAULT_MASTER_SERVER_PORT is used if ommited
	port = 0;
	strlcpy(host, master, sizeof(host));
	if ((column = strchr(host, ':')))
	{
		column[0] = 0; // truncate host name
		port = atoi(column + 1); // get port for real
	}
	port = (port > 0 && port < 65535) ? port : QW_DEFAULT_MASTER_SERVER_PORT;

	if (!host[0])
	{
		Sys_Printf("failed to add master server: %s\n", master);
		return false; // empty host name, not funny
	}

	if (!NET_GetSockAddrIn_ByHostAndPort(&addr, host, port))
	{
		Sys_Printf("failed to add master server: %s\n", master);
		return false;
	}

	if (QRY_Master_ByAddr(&addr))
	{
		Sys_Printf("failed to add master server: %s - already added!\n", master);
		return false;
	}

	for (i = 0, m = masters.master; i < MAX_MASTERS; i++, m++)
	{
		if (m->state == ms_used)
			continue; // master slot used

		memset(m, 0, sizeof(*m)); // reset data in slot

		m->state = ms_used;
		m->addr = addr;

		Sys_Printf("master server added: %s\n", master);
		return true;
	}

	Sys_Printf("failed to add master server: %s\n", master);
	return false;
}

static void QRY_Cmd_Heartbeat_f(void)
{
	masters.last_heartbeat = time(NULL) - QW_MASTER_HEARTBEAT_SECONDS - 1; // trigger heartbeat ASAP
}

// clear masters
static void QRY_MastersInit(void)
{
	memset(&masters, 0, sizeof(masters));
	masters.init_time = time(NULL);

	QRY_Cmd_Heartbeat_f();  // trigger heartbeat ASAP
}

// check if "masters" or "masters_query" cvar changed and do appropriate action
static void QRY_CheckMastersModified(void)
{
	char *mlist;

	// for fix issues with DNS and such force masters re-init time to time
	if (time(NULL) - masters.init_time > QW_MASTERS_FORCE_RE_INIT)
	{
		Sys_DPrintf("forcing masters re-init\n");
		masters_list->modified = true;
	}

	// "masters" and "masters_query" was not modified, do nothing
	if (!masters_list->modified && !masters_query->modified)
		return;

	// clear masters
	QRY_MastersInit();

	// add all masters
	for ( mlist = masters_list->string; (mlist = COM_Parse(mlist)); )
	{
		QRY_AddMaster(com_token);
	}

	masters_list->modified = masters_query->modified = false;
}

// query master servers
static void QRY_QueryMasters(void)
{
	int			i;
	master_t	*m;
	time_t		current_time = time(NULL);
	char		buf[] = "xxx.xxx.xxx.xxx:xxxxx";

	// do we need query masters?
	if (!masters_query->integer)
		return;

	for (i = 0, m = masters.master; i < MAX_MASTERS; i++, m++)
	{
		if (m->state != ms_used)
			continue; // master slot not used

		if (current_time <= m->next_query)
			continue; // not yet

		Sys_DPrintf("query master: %s\n", NET_AdrToString(&m->addr, buf, sizeof(buf)));
		
		NET_SendPacket(net_socket, sizeof(QW_MASTER_QUERY), QW_MASTER_QUERY, &m->addr);
		m->next_query = current_time + QW_MASTER_QUERY_TIME_SHORT; // delay next query for some time
	}
}

// heartbeat master servers.
// send a message to the master every few minutes.
static void QRY_HeartbeatMasters(void)
{
	char		string[128];
	int			i, len;
	master_t	*m;
	time_t		current_time = time(NULL);
	char		buf[] = "xxx.xxx.xxx.xxx:xxxxx";

	// do we need heartbeat masters?
	if (!masters_heartbeat->integer)
		return;

	if (current_time < masters.last_heartbeat + QW_MASTER_HEARTBEAT_SECONDS)
		return; // not yet
	
	masters.last_heartbeat = current_time;
	masters.heartbeat_sequence++;
	snprintf(string, sizeof(string), "%c\n%i\n%i\n", S2M_HEARTBEAT, masters.heartbeat_sequence, FWD_peers_count());
	len = strlen(string);

	if (developer->integer > 1)
		Sys_DPrintf("heartbeat:\n%s\n", string);

	for (i = 0, m = masters.master; i < MAX_MASTERS; i++, m++)
	{
		if (m->state != ms_used)
			continue; // master slot not used
		
		Sys_DPrintf("heartbeat master: %s\n", NET_AdrToString(&m->addr, buf, sizeof(buf)));
		NET_SendPacket(net_socket, len, string, &m->addr);
	}
}

qbool QRY_IsMasterReply(void)
{
	if (net_message.cursize < 6 || memcmp(net_message.data, "\xff\xff\xff\xff\x64\x0a", 6))
		return false;

	return true;
}

static server_t	*QRY_SV_new(const char *remote_host, int remote_port, qbool link); // forward reference

void SVC_QRY_ParseMasterReply(void)
{
    int				i, c;
	master_t		*m;
	int				ret = net_message.cursize;
	unsigned char	*answer = net_message.data; // not the smartest way, but why copy from one place to another...

	// no point to parse it, we do not query masters
	if (!masters_query->integer)
	{
		Sys_DPrintf("master server reply ignored\n");
		return;
	}

	Sys_DPrintf ("master server reply from %s:%d\n", inet_ntoa(net_from.sin_addr), (int)ntohs(net_from.sin_port));

	// is it reply from registered master server or someone trying to do some evil things?
	for (i = 0, m = masters.master; i < MAX_MASTERS; i++, m++)
	{
		if (m->state != ms_used)
			continue; // master slot not used

		if (NET_CompareAddress(&net_from, &m->addr))
		{
			// OK - it is reply from registered master server
			m->next_query = time(NULL) + QW_MASTER_QUERY_TIME; // delay next query for some time
			break;
		}
	}

	if (i >= MAX_MASTERS)
	{
		Sys_Printf("Reply from not registered master server\n");
		return;
	}

	Sys_DPrintf("master server returned %d bytes\n", ret);

	for (c = 0, i = 6; i + 5 < ret; i += 6, c++)
	{
		char ip[64];
		int port = 256 * (int)answer[i+4] + (int)answer[i+5];

		snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
			(int)answer[i+0], (int)answer[i+1],
			(int)answer[i+2], (int)answer[i+3]);

		if (developer->integer > 1)
			Sys_DPrintf("SERVER: %4d %s:%d\n", c, ip, port);

		QRY_SV_new(ip, port, true);
	}
}

//========================================

static struct sockaddr_in *QRY_FL_Filtered(struct sockaddr_in *addr); // forward reference

static int QRY_SV_Count(void)
{
	return sv_count;
}

// return server by pseudo index
static server_t	*QRY_SV_ByIndex(int idx)
{
	server_t	*sv;

	if (idx < 0)
		return NULL;

	for (sv = servers; sv; sv = sv->next, idx--)
		if (!idx)
			return sv;

	return NULL;
}

static server_t	*QRY_SV_ByAddrEx(struct sockaddr_in *addr, qbool base)
{
	// use different compare function.
	typedef		qbool (*net_cmp_func)(struct sockaddr_in *a, struct sockaddr_in *b);
	net_cmp_func cmp_func = base ? NET_CompareBaseAddress : NET_CompareAddress;

	server_t	*sv;

	for (sv = servers; sv; sv = sv->next)
		if ((*cmp_func)(addr, &sv->addr))
			return sv;

	return NULL;
}

static server_t	*QRY_SV_ByAddr(struct sockaddr_in *addr)
{
	return QRY_SV_ByAddrEx(addr, false);
}

static server_t	*QRY_SV_new(const char *remote_host, int remote_port, qbool link)
{
	server_t			*sv;
	struct sockaddr_in	addr;

	if (QRY_SV_Count() >= MAX_SERVERS)
		return NULL;

	if (!NET_GetSockAddrIn_ByHostAndPort(&addr, remote_host, remote_port))
		return NULL; // failed to resolve host name?

	if ((sv = QRY_SV_ByAddr(&addr)))
		return NULL; // we already have such server on list

	if (QRY_FL_Filtered(&addr))
	{
		char buf[] = "xxx.xxx.xxx.xxx:xxxxx";
		Sys_DPrintf("filtered: %s\n", NET_AdrToString(&addr, buf, sizeof(buf)));
		return NULL; // filtered
	}

	sv_count++;

	sv = Sys_malloc(sizeof(*sv));
	sv->addr = addr;
	sv->ping = 0xFFFF; // mark as unreachable

	if (link)
	{
		sv->next = servers;
		servers = sv;
	}

	return sv;
}

// free server data, perform unlink if requested
static void QRY_SV_free(server_t *sv, qbool unlink)
{
	if (!sv)
		return;

	if (unlink)
	{
		server_t *next, *prev, *current;

		prev = NULL;
		current = servers;

		for ( ; current; )
		{
			next = current->next;

			if (sv == current)
			{
				if (prev)
					prev->next = next;
				else
					servers = next;

				break;
			}

			prev = current;
			current = next;
		}
	}

	// free all data related to server
	if (sv->hop2)
		Sys_free(sv->hop2);

	Sys_free(sv);

	sv_count--;
}

//==============================================
// ping quality window: circular buffer of the last PING_QUALITY_WINDOW
// direct-ping outcomes for a server (rtt in ms, or -1 for a lost packet).
// Accumulated over the existing ~60s ping cadence in QRY_SV_PingServers -
// no extra probe traffic - so avg/jitter/loss are derived from real,
// naturally-occurring samples rather than a synthetic burst.

static void QRY_Quality_AddSample(server_t *sv, short sample)
{
	if (!sv)
		return;

	sv->ping_samples[sv->ping_samples_next] = sample;
	sv->ping_samples_next = (sv->ping_samples_next + 1) % PING_QUALITY_WINDOW;
	if (sv->ping_samples_count < PING_QUALITY_WINDOW)
		sv->ping_samples_count++;
}

// computes avg/min/max/jitter (population stddev, integer ms) and loss
// percent (0-100) over the current sample window. Returns false (all
// outputs zeroed) if there are no samples yet - caller must check this
// before trusting the outputs, since "no data" and "0ms/0% loss" are not
// the same thing.
static qbool QRY_Quality_Compute(const server_t *sv, int *avg, int *jitter, int *loss_pct)
{
	int i, n = 0, sum = 0, sumsq_scaled = 0;
	int received = 0;

	*avg = 0;
	*jitter = 0;
	*loss_pct = 0;

	if (!sv || sv->ping_samples_count <= 0)
		return false;

	for (i = 0; i < sv->ping_samples_count; i++)
	{
		short s = sv->ping_samples[i];
		if (s >= 0)
		{
			sum += s;
			received++;
		}
	}
	n = sv->ping_samples_count;

	*loss_pct = (int) (100 - (100 * received) / n);

	if (received <= 0)
		return true; // 100% loss, no rtt stats possible

	*avg = sum / received;

	// population variance over received samples only (loss doesn't have an
	// rtt to contribute to jitter) - fixed-point (x10) to keep this integer
	// math without pulling in <math.h> sqrt for a small embedded daemon
	for (i = 0; i < sv->ping_samples_count; i++)
	{
		short s = sv->ping_samples[i];
		if (s >= 0)
		{
			int diff = s - *avg;
			sumsq_scaled += diff * diff;
		}
	}
	{
		int variance = sumsq_scaled / received;
		// integer sqrt (Newton's method, converges in a handful of
		// iterations for the small values ping jitter produces)
		int x = variance;
		int y = (x + 1) / 2;
		while (y < x)
		{
			x = y;
			y = (x + variance / x) / 2;
		}
		*jitter = x;
	}

	return true;
}

static void QRY_SV_PingServers(void)
{
	static int		idx;
	static double	last;

	double			current = Sys_DoubleTime(); // we need double time for ping measurement
	server_t		*sv;

	// do not ping servers since we do not query masters
	if (!masters_query->integer)
		return;

	if (!servers)
		return; // nothing to do

	if (current - last < QW_SERVER_RATE)
		return; // do not ping servers too fast

	last = current;

	idx = (int)max(0, idx);
	sv = QRY_SV_ByIndex(idx++);
	if (!sv)
		sv = QRY_SV_ByIndex(idx = 0); // can't find server by index, try with index 0

	if (!sv)
		return; // hm, should not be the case...

	// check for dead server
	if (!sv->reply && sv->ping_sent_at - sv->ping_reply_at > QW_SERVER_DEAD_TIME)
	{
		Sys_DPrintf("dead -> %s:%d\n", inet_ntoa(sv->addr.sin_addr), (int)ntohs(sv->addr.sin_port));

		QRY_SV_free(sv, true); // remove damn server, however master server may add it back...
		idx--; // step back index
		return;
	}

	if (sv->ping_sent_at && current - sv->ping_sent_at < QW_SERVER_MIN_PING_REQUEST_TIME)
		return; // do not spam server

	// about to send a new probe: if the PREVIOUS one never got a reply,
	// that is a genuine lost packet - record it as a failed sample (-1)
	// before overwriting ping_sent_at, so quality stats reflect real loss
	// accumulated over the natural ping cadence, without any extra traffic
	if (sv->ping_sent_at && !sv->reply)
		QRY_Quality_AddSample(sv, -1);

	sv->ping_sent_at = current; // remember when we sent ping
	sv->reply = false; // reset reply flag

	NET_SendPacket(net_socket, sizeof(QW_SERVER_PING_QUERY)-1, QW_SERVER_PING_QUERY, &sv->addr);
//	Sys_Printf("ping(%3d) -> %s:%d\n", idx, inet_ntoa(sv->addr.sin_addr), (int)ntohs(sv->addr.sin_port));
}

void QRY_SV_PingReply(void)
{
	server_t *sv = NULL;

	// ignore server ping reply since we do not query masters and can't keep server list up2date
	if (!masters_query->integer)
	{
		Sys_DPrintf("server reply ignored\n");
		return;
	}

	sv = QRY_SV_ByAddr(&net_from);

	// Only one reply belongs to each probe.  Ignoring unsolicited and
	// duplicate packets prevents a sender from biasing avg/jitter/loss.
	if (sv && sv->ping_sent_at > 0 && !sv->reply)
	{
		double current = Sys_DoubleTime();
		double ping = current - sv->ping_sent_at;

		sv->ping = (int)max(0, 1000.0 * ping);
		sv->ping_reply_at = current;
		sv->reply = true;

		QRY_Quality_AddSample(sv, (short) sv->ping);

//		Sys_Printf("ping <- %s:%d, %d\n", inet_ntoa(net_from.sin_addr), (int)ntohs(net_from.sin_port), sv->ping);
	}
	else
	{
//		Sys_Printf("ping <- %s:%d, not registered server\n", inet_ntoa(net_from.sin_addr), (int)ntohs(net_from.sin_port));
	}
}

void SVC_QRY_PingStatus(void)
{
	static sizebuf_t buf; // static  - so it not allocated each time
	static byte		buf_data[MSG_BUF_SIZE]; // static  - so it not allocated each time

	server_t		*sv;

	SZ_InitEx(&buf, buf_data, sizeof(buf_data), true);

	MSG_WriteLong(&buf, -1);	// -1 sequence means out of band
	MSG_WriteChar(&buf, A2C_PRINT);

	// if we does not query masters then we can't proved reliable info, so do not send servers list
	if (masters_query->integer)
	{
		for (sv = servers; sv; sv = sv->next)
		{
			MSG_WriteLong(&buf, *(int *)&sv->addr.sin_addr);
			MSG_WriteShort(&buf, (short)ntohs(sv->addr.sin_port));
			MSG_WriteShort(&buf, (short)sv->ping);
		}
	}

	if (buf.overflowed)
	{
		Sys_Printf("SVC_QRY_PingStatus: overflow\n");
		return; // overflowed
	}

	// send the datagram
	NET_SendPacket(net_from_socket, buf.cursize, buf.data, &net_from);
}

//==============================================
// mesh wire format:
//   probe query  (text, via normal dispatch): "meshprobe <nonce>"
//   probe reply  (binary): 0xFF*4 'Q' 'M' <type=1><nonce:4 LE> +
//       N*(int32 ip + int16 port + int16 avg_ping + int16 jitter + int16 loss_pct)
//   meshstatus reply (binary, collector-facing): 0xFF*4 'Q' 'M' <type=2><reserved:4> +
//       repeated: (int32 peer_ip + int16 peer_port + int16 age_seconds + int16 count) +
//       count*(int32 ip + int16 port + int16 avg_ping + int16 jitter + int16 loss_pct)
//
// Both replies are rate-limited per source address to avoid this becoming a
// UDP amplification reflector: a forged-source flood of probe/meshstatus
// queries gets at most one reply per address per RATE_LIMIT_WINDOW.

#define MESH_RATE_LIMIT_WINDOW 1.0		// seconds
#define MESH_RATE_LIMIT_TRACK 64		// small ring of recently answered addresses
#define MESH_RATE_LIMIT_AGGREGATE 64	// max total mesh replies/sec across ALL sources combined

typedef struct mesh_rate_entry_s
{
	struct sockaddr_in	addr;
	double				last_reply_at;
} mesh_rate_entry_t;

static mesh_rate_entry_t mesh_rate_track[MESH_RATE_LIMIT_TRACK];
static int mesh_rate_track_next;

// global budget on top of the per-source ring: the ring alone only stops a
// single spoofed source from being answered twice, but a flood that cycles
// through MESH_RATE_LIMIT_TRACK+1 forged addresses evicts entries before
// they age out and gets ~1 reply per packet regardless of source diversity.
// This caps total mesh replies/sec no matter how many distinct (real or
// spoofed) sources are involved.
static double mesh_rate_aggregate_window_start;
static int mesh_rate_aggregate_count;

static qbool QRY_Mesh_AggregateRateLimited(double current)
{
	if (current - mesh_rate_aggregate_window_start >= MESH_RATE_LIMIT_WINDOW)
	{
		mesh_rate_aggregate_window_start = current;
		mesh_rate_aggregate_count = 0;
	}

	if (mesh_rate_aggregate_count >= MESH_RATE_LIMIT_AGGREGATE)
		return true;

	mesh_rate_aggregate_count++;
	return false;
}

// true if we already replied to this address recently (and records this
// reply for future calls) - a crude per-source token bucket, good enough to
// kill a naive amplification flood without adding real state/memory growth
static qbool QRY_Mesh_RateLimited(const struct sockaddr_in *from)
{
	double current = Sys_DoubleTime();
	int i;

	if (QRY_Mesh_AggregateRateLimited(current))
		return true;

	for (i = 0; i < MESH_RATE_LIMIT_TRACK; i++)
	{
		if (mesh_rate_track[i].last_reply_at == 0)
			continue;

		if (NET_CompareBaseAddress((struct sockaddr_in *) from, &mesh_rate_track[i].addr))
		{
			if (current - mesh_rate_track[i].last_reply_at < MESH_RATE_LIMIT_WINDOW)
				return true;

			mesh_rate_track[i].last_reply_at = current;
			return false;
		}
	}

	// not tracked yet, take the next ring slot
	mesh_rate_track[mesh_rate_track_next].addr = *from;
	mesh_rate_track[mesh_rate_track_next].last_reply_at = current;
	mesh_rate_track_next = (mesh_rate_track_next + 1) % MESH_RATE_LIMIT_TRACK;

	return false;
}

// answers a "meshprobe <nonce>" query. This is what makes protocol-based
// mesh detection possible: only a qwfwd binary running this code replies in
// this exact format, so QRY_Mesh_HandleReply() on the caller's side treating
// "got a valid reply" as "this is a qwfwd" is sound, not a guess.
void SVC_QRY_MeshProbe(void)
{
	char				*nonce_str;
	unsigned int		nonce;
	static sizebuf_t	buf;
	static byte			buf_data[MAX_MSGLEN];
	server_t			*sv;
	int					entries_written = 0;

	if (!mesh_enable->integer || !masters_query->integer)
		return; // mesh disabled or we don't keep an authoritative server list to report

	// validate the request BEFORE spending rate-limit budget on it - a
	// malformed query costs us nothing to reject, so it should not consume
	// the same 1-per-second slot a legitimate probe would need
	nonce_str = Cmd_Argv(1);
	if (!nonce_str[0])
		return; // malformed query, no nonce to echo back

	nonce = (unsigned int) strtoul(nonce_str, NULL, 10);
	if (!nonce)
		return;

	if (QRY_Mesh_RateLimited(&net_from))
		return;

	SZ_InitEx(&buf, buf_data, sizeof(buf_data), true);

	MSG_WriteLong(&buf, -1);
	MSG_WriteByte(&buf, (byte) MESH_MAGIC0);
	MSG_WriteByte(&buf, (byte) MESH_MAGIC1);
	MSG_WriteByte(&buf, MESH_MSG_PINGSTATUS_REPLY);
	MSG_WriteLong(&buf, (int) nonce);

	// report OUR OWN directly-measured pings to known servers, WITH quality
	// (avg/jitter/loss over the accumulated sample window, see
	// QRY_Quality_Compute) - this is the 1-hop data this peer contributes to
	// whoever is probing us. Entry is now 12 bytes: ip(4) port(2) avg_ping(2)
	// jitter(2) loss_pct(2). Servers with no samples yet (freshly discovered,
	// window still empty) are skipped rather than reported with fabricated
	// zeros - "no data" must not look identical to "0ms/0% loss".
	for (sv = servers; sv && !buf.overflowed; sv = sv->next)
	{
		int avg, jitter, loss_pct;

		if (!QRY_Quality_Compute(sv, &avg, &jitter, &loss_pct))
			continue; // no samples yet for this server

		if (loss_pct >= 100)
			continue; // fully unreachable, nothing useful to report

		if (entries_written >= MESH_MAX_HOP2_PER_PEER)
			break; // cap response size, headroom checked against MAX_MSGLEN below regardless

		if (buf.cursize + 12 > (int) sizeof(buf_data) - 16)
			break; // would not fit a whole entry in this single UDP datagram, stop rather than fragment IP

		MSG_WriteLong(&buf, QRY_IPv4AsInt(&sv->addr.sin_addr));
		MSG_WriteShort(&buf, (short) ntohs(sv->addr.sin_port));
		MSG_WriteShort(&buf, (short) avg);
		MSG_WriteShort(&buf, (short) jitter);
		MSG_WriteShort(&buf, (short) loss_pct);
		entries_written++;
	}

	if (buf.overflowed)
	{
		Sys_Printf("SVC_QRY_MeshProbe: overflow, truncated response\n");
		return;
	}

	NET_SendPacket(net_from_socket, buf.cursize, buf.data, &net_from);
}

// answers "meshstatus [start_index]": exposes the hop2 cache (pings
// reported by OUR mesh peers about THEIR neighbours) to an external
// collector building the worldwide route map.
//
// Real pagination, not a silent truncation: the response is bounded by
// MAX_MSGLEN (the actual QW/UDP wire limit - MSG_BUF_SIZE is just a local
// scratch buffer and is NOT safe to use as the network size cap, a full
// buffer's worth would fragment at the IP layer and can be dropped by
// firewalls/routers in between). start_index selects which mesh peer to
// begin listing from (servers list order); the reply ends with a
// next_index field so the collector can keep calling "meshstatus N" until
// it gets next_index == -1 (all peers covered).
void SVC_QRY_MeshStatus(void)
{
	static sizebuf_t	buf;
	static byte			buf_data[MAX_MSGLEN];
	server_t			*sv;
	double				current;
	char				*arg;
	int					start_index, index, next_index;
	int					next_index_offset;

	if (!mesh_enable->integer)
		return;

	if (QRY_Mesh_RateLimited(&net_from))
		return;

	arg = Cmd_Argv(1);
	if (arg[0])
	{
		long parsed = strtol(arg, NULL, 10);
		start_index = (parsed < 0) ? 0 : (parsed > INT_MAX) ? INT_MAX : (int) parsed;
	}
	else
	{
		start_index = 0;
	}

	current = Sys_DoubleTime();

	SZ_InitEx(&buf, buf_data, sizeof(buf_data), true);

	MSG_WriteLong(&buf, -1);
	MSG_WriteByte(&buf, (byte) MESH_MAGIC0);
	MSG_WriteByte(&buf, (byte) MESH_MAGIC1);
	MSG_WriteByte(&buf, MESH_MSG_MESHSTATUS_REPLY);
	MSG_WriteLong(&buf, 0); // reserved
	next_index_offset = buf.cursize;
	MSG_WriteLong(&buf, -1); // next_index placeholder, patched below once known

	next_index = -1;
	index = 0;

	for (sv = servers; sv; sv = sv->next, index++)
	{
		int i, age, count;
		int block_start;

		if (index < start_index)
			continue;

		if (!sv->is_mesh || sv->hop2_count <= 0)
			continue;

		count = sv->hop2_count;
		if (count > MESH_MAX_HOP2_PER_PEER)
			count = MESH_MAX_HOP2_PER_PEER;

		age = (int) (current - sv->mesh_reply_at);
		if (age < 0) age = 0;
		if (age > 0x7FFF) age = 0x7FFF;

		block_start = buf.cursize;

		// bail out BEFORE starting a peer block we can't finish whole -
		// a collector must never see a truncated peer's neighbour list.
		// Leave headroom for the trailing OOB overhead so this stays a
		// single unfragmented UDP datagram. Each hop2 entry is now 12 bytes
		// (ip+port+ping+jitter+loss_pct).
		if (block_start + 10 + count * 12 > (int) sizeof(buf_data) - 16)
		{
			next_index = index; // caller resumes here with "meshstatus <next_index>"
			break;
		}

		MSG_WriteLong(&buf, QRY_IPv4AsInt(&sv->addr.sin_addr));
		MSG_WriteShort(&buf, (short) ntohs(sv->addr.sin_port));
		MSG_WriteShort(&buf, (short) age);
		MSG_WriteShort(&buf, (short) count);

		for (i = 0; i < count; i++)
		{
			MSG_WriteLong(&buf, QRY_IPv4AsInt(&sv->hop2[i].addr.sin_addr));
			MSG_WriteShort(&buf, (short) ntohs(sv->hop2[i].addr.sin_port));
			MSG_WriteShort(&buf, (short) sv->hop2[i].ping);
			MSG_WriteShort(&buf, (short) sv->hop2[i].jitter);
			MSG_WriteShort(&buf, (short) sv->hop2[i].loss_pct);
		}
	}

	// patch the next_index placeholder now that it is known - buf.data is
	// the same backing array the earlier MSG_WriteLong targeted, safe to
	// overwrite in place since sizebuf_t is a flat byte buffer
	buf.data[next_index_offset + 0] = (byte) (next_index & 0xff);
	buf.data[next_index_offset + 1] = (byte) ((next_index >> 8) & 0xff);
	buf.data[next_index_offset + 2] = (byte) ((next_index >> 16) & 0xff);
	buf.data[next_index_offset + 3] = (byte) ((next_index >> 24) & 0xff);

	if (buf.overflowed)
	{
		Sys_Printf("SVC_QRY_MeshStatus: overflow\n");
		return;
	}

	NET_SendPacket(net_from_socket, buf.cursize, buf.data, &net_from);
}

//==============================================
// server filters.
// _FL_ stands for filter.

static void QRY_FL_Init(void)
{
	memset(&server_filter, 0, sizeof(server_filter));
}

static struct sockaddr_in *QRY_FL_Filtered(struct sockaddr_in *addr)
{
	int						i;

	for (i = 0; i < server_filter.count; i++)
	{
		if (NET_CompareBaseAddress(addr, &server_filter.addr[i]))
			return &server_filter.addr[i];
	}

	return NULL;
}

static qbool QRY_FL_AddFilter(const char *filter)
{
	struct sockaddr_in		addr;
	char					host[1024], *column;

	if (server_filter.count >= MAX_SV_FILTERS)
	{
		Sys_Printf("failed to add server filter: %s - filter list are full!\n", filter);
		return false;
	}

	// get host name.
	strlcpy(host, filter, sizeof(host));
	if ((column = strchr(host, ':')))
	{
		column[0] = 0; // get rid of port.
	}

	if (!host[0])
	{
		Sys_Printf("failed to add server filter: %s\n", filter);
		return false; // empty host name, not funny
	}

	if (!NET_GetSockAddrIn_ByHostAndPort(&addr, host, 0))
	{
		Sys_Printf("failed to add server filter: %s\n", filter);
		return false;
	}

	if (QRY_FL_Filtered(&addr))
	{
		Sys_Printf("failed to add server filter: %s - already added!\n", filter);
		return false;
	}

	server_filter.addr[server_filter.count] = addr;
	server_filter.count++;

	Sys_Printf("server filter added: %s\n", filter);
	return true;
}

static void QRY_FL_RemoveFilteredServers(void)
{
	int			i;
	server_t	*sv;

	for (i = 0; i < server_filter.count; i++)
	{
		if ((sv = QRY_SV_ByAddrEx(&server_filter.addr[i], true)))
		{
			char buf[] = "xxx.xxx.xxx.xxx:xxxxx";
			Sys_DPrintf("filtered: %s\n", NET_AdrToString(&sv->addr, buf, sizeof(buf)));
			QRY_SV_free(sv, true);
		}
	}
}

// check if "masters_filter_servers" cvar changed and do appropriate action
static void QRY_FL_CheckVarsModified(void)
{
	char *mlist;

	// "masters_filter_servers" was not modified, do nothing
	if (!masters_filter_servers->modified)
		return;

	// clear filters
	QRY_FL_Init();

	// add all filters
	for ( mlist = masters_filter_servers->string; (mlist = COM_Parse(mlist)); )
	{
		QRY_FL_AddFilter(com_token);
	}

	// remove filtered servers if any.
	QRY_FL_RemoveFilteredServers();

	masters_filter_servers->modified = false;
}

//==============================================

static void QRY_Cmd_SvList_f(void)
{
	server_t	*sv;
	int idx;
	char ipport[] = "xxx.xxx.xxx.xxx:xxxxx";

	Sys_Printf("=== server list ===\n");
	Sys_Printf("### %-*s ping\n", sizeof(ipport)-1, "address");
	Sys_Printf("--------------------------------------\n");

	for (idx = 1, sv = servers; sv; sv = sv->next, idx++)
	{
		Sys_Printf("%3d %-*s %d\n",
			idx, sizeof(ipport)-1, NET_AdrToString(&sv->addr, ipport, sizeof(ipport)), (int)sv->ping);
	}

	Sys_Printf("--------------------------------------\n");
	Sys_Printf("%d servers\n", idx-1);
}

//==============================================
// mesh: discover other qwfwd instances among known servers, probe them with
// the existing "pingstatus" query, and cache the 2-hop ping data they report
// for their own neighbours. Detection is protocol-based (does the target
// answer with a valid mesh reply?), not a version-string guess - a plain QW
// server or mvdsv simply won't understand "pingstatus" and will not reply
// in our expected format, so it is never misclassified as mesh-capable.
// generates a nonzero 32-bit nonce; 0 is reserved for "no outstanding probe"
// ponytail: rand()-seeded, same as the existing svc.c challenge generator -
// predictable to an attacker who can guess process start time/call count.
// Upgrade path: OS CSPRNG (CryptGenRandom/getrandom) if a stronger anti-spoof
// guarantee than the per-source+aggregate rate limit above is ever needed.
static unsigned int QRY_Mesh_NewNonce(void)
{
	unsigned int nonce;

	do
	{
		nonce = ((unsigned int) rand() << 16) ^ (unsigned int) rand();
	} while (!nonce);

	return nonce;
}

// capacity-doubling append, avoids a realloc() per received entry which
// would fragment the heap on a long-running daemon
static void QRY_Mesh_StoreHop2(server_t *sv, struct sockaddr_in *addr, int ping, int jitter, int loss_pct)
{
	int i;

	if (!sv || ping < 0)
		return;

	// drop self-references: a peer reporting a ping to itself (its own
	// address in its own self-reported list) is not a routable edge and
	// would otherwise show up as a spurious 0ms "next hop" pointing back
	// at the same node - a naive collector could pick it as the "best"
	// route to itself
	if (NET_CompareAddress(&sv->addr, addr))
		return;

	// update existing entry for the same target instead of duplicating
	for (i = 0; i < sv->hop2_count; i++)
	{
		if (NET_CompareAddress(&sv->hop2[i].addr, addr))
		{
			sv->hop2[i].ping = ping;
			sv->hop2[i].jitter = jitter;
			sv->hop2[i].loss_pct = loss_pct;
			return;
		}
	}

	if (sv->hop2_count >= MESH_MAX_HOP2_PER_PEER)
		return; // hard cap, silently drop extra entries from a chatty/malicious peer

	if (sv->hop2_count >= sv->hop2_capacity)
	{
		int new_capacity = sv->hop2_capacity ? sv->hop2_capacity * 2 : 16;
		hop2_entry_t *grown;

		if (new_capacity > MESH_MAX_HOP2_PER_PEER)
			new_capacity = MESH_MAX_HOP2_PER_PEER;

		grown = realloc(sv->hop2, new_capacity * sizeof(hop2_entry_t));
		if (!grown)
			return; // allocation failed, drop this entry, keep what we already have

		sv->hop2 = grown;
		sv->hop2_capacity = new_capacity;
	}

	sv->hop2[sv->hop2_count].addr = *addr;
	sv->hop2[sv->hop2_count].ping = ping;
	sv->hop2[sv->hop2_count].jitter = jitter;
	sv->hop2[sv->hop2_count].loss_pct = loss_pct;
	sv->hop2_count++;
}

// probe servers we haven't classified yet, one probe per call (round-robin,
// throttled), same shape as QRY_SV_PingServers - never blocks the main loop
static void QRY_Mesh_QueryPeers(void)
{
	static int		idx;
	static double	last;
	double			current = Sys_DoubleTime();
	server_t		*sv;
	int				count, i;

	if (!mesh_enable->integer || !masters_query->integer)
		return;

	if (!servers)
		return;

	// same throttle shape as QRY_SV_PingServers (QW_SERVER_RATE): without
	// this, a fresh boot with hundreds of newly-discovered servers (none
	// yet mesh_probed) would fire one probe per main-loop iteration back
	// to back, a real startup burst the per-target interval alone does not
	// prevent (that interval only rate-limits re-probes of the SAME
	// target, not the aggregate rate across all targets)
	if (current - last < QW_SERVER_RATE)
		return;
	last = current;

	count = QRY_SV_Count();
	if (count <= 0)
		return;

	idx = (int) max(0, idx) % count;
	sv = QRY_SV_ByIndex(idx++);
	if (idx >= count)
		idx = 0;

	if (!sv)
		return;

	// drop a stale outstanding probe so we can retry later
	if (sv->mesh_nonce && current - sv->mesh_probe_sent_at > MESH_PENDING_TIMEOUT)
		sv->mesh_nonce = 0;

	if (sv->mesh_nonce)
		return; // probe already in flight for this server

	{
		double interval = sv->is_mesh ? mesh_query_interval->value : mesh_probe_interval->value;

		if (sv->mesh_probed && current - sv->mesh_probe_sent_at < interval)
			return; // too soon to re-probe
	}

	// the probe itself is plain text (goes through the normal
	// SV_ConnectionlessPacket dispatch on the remote qwfwd, same as any
	// other out-of-band command) - only the REPLY is binary, which is why
	// only the reply needs the special interception in svc.c
	sv->mesh_nonce = QRY_Mesh_NewNonce();
	sv->mesh_probe_sent_at = current;
	sv->mesh_probed = true;

	{
		char packet[32];
		int  len = snprintf(packet, sizeof(packet), "\xff\xff\xff\xff%s %u", MESH_PROBE_CMD, sv->mesh_nonce);

		NET_SendPacket(net_socket, len, packet, &sv->addr);
	}

	// mark other servers that already timed out too, so a single slow
	// mesh doesn't starve the round-robin (cheap opportunistic sweep)
	for (i = 0, sv = servers; sv; sv = sv->next, i++)
	{
		if (sv->mesh_nonce && current - sv->mesh_probe_sent_at > MESH_PENDING_TIMEOUT)
			sv->mesh_nonce = 0;
	}
}

// finds the server_t that has this nonce as its outstanding probe -
// this IS the anti-spoofing check: an off-path attacker forging net_from
// still needs to guess a live 32-bit nonce tied to a specific pending
// probe, not just "any address in our server list"
static server_t *QRY_Mesh_ByNonce(unsigned int nonce)
{
	server_t *sv;

	if (!nonce)
		return NULL;

	for (sv = servers; sv; sv = sv->next)
		if (sv->mesh_nonce == nonce)
			return sv;

	return NULL;
}

qbool QRY_Mesh_IsMeshReply(void)
{
	if (net_message.cursize < 6)
		return false;

	return net_message.data[4] == MESH_MAGIC0 && net_message.data[5] == MESH_MAGIC1;
}

// parses a MESH_MSG_PINGSTATUS_REPLY payload: strictly-validated sequence of
// 12-byte records (int32 raw IP + int16 port host-order + int16 avg_ping,
// int16 jitter and int16 loss percentage).
// every read is bounds-checked against buflen before touching memory; a
// truncated trailing record (buflen not a multiple of 12) is ignored rather
// than read out of bounds. Entry layout: ip(4) port(2) avg_ping(2)
// jitter(2) loss_pct(2) = 12 bytes.
static void QRY_Mesh_ParsePingStatusPayload(server_t *sv, const byte *buf, size_t buflen)
{
	size_t offset = 0;

	while (offset + 12 <= buflen)
	{
		struct sockaddr_in addr;
		unsigned short port_h;
		short ping, jitter, loss_pct;

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		memcpy(&addr.sin_addr, buf + offset, 4); // raw network-order bytes, explicit copy (no pointer punning)

		port_h = (unsigned short) (buf[offset+4] | (buf[offset+5] << 8));
		addr.sin_port = htons(port_h);

		ping = (short) (buf[offset+6] | (buf[offset+7] << 8));
		jitter = (short) (buf[offset+8] | (buf[offset+9] << 8));
		loss_pct = (short) (buf[offset+10] | (buf[offset+11] << 8));

		if (ping >= 0 && jitter >= 0 && loss_pct >= 0 && loss_pct <= 100)
			QRY_Mesh_StoreHop2(sv, &addr, ping, jitter, loss_pct);

		offset += 12;
	}
}

// entry point called from svc.c once QRY_Mesh_IsMeshReply() has already
// confirmed the wire marker; still re-validates everything because the
// marker alone is not proof of authenticity
void QRY_Mesh_HandleReply(void)
{
	const byte		*data = net_message.data;
	int				len = net_message.cursize;
	byte			type;
	unsigned int	nonce;
	server_t		*sv;

	if (len < 11) // 4 (oob) + 2 (magic) + 1 (type) + 4 (nonce) = 11 bytes exactly, zero-entry replies are exactly this length
		return;

	if ((len - 11) % 12 != 0)
		return; // trailing bytes not a whole number of 12-byte entries: malformed/truncated, reject the whole reply rather than parse a partial one

	type = data[6];

	nonce = (unsigned int)data[7] |
		((unsigned int)data[8] << 8) |
		((unsigned int)data[9] << 16) |
		((unsigned int)data[10] << 24);

	if (type != MESH_MSG_PINGSTATUS_REPLY)
		return; // we only ever expect this type as a client-side probe reply

	sv = QRY_Mesh_ByNonce(nonce);
	if (!sv)
		return; // no matching outstanding probe: forged, stale, or duplicate reply - drop silently

	if (!NET_CompareAddress(&net_from, &sv->addr))
		return; // nonce matched a different address than the wire source - drop

	sv->mesh_nonce = 0; // consume the nonce, one reply per probe
	sv->is_mesh = true;
	sv->mesh_reply_at = Sys_DoubleTime();

	// A probe reply is a complete snapshot of this peer's current
	// measurements, not a delta.  Drop entries which disappeared from the
	// newest reply instead of keeping unroutable/stale edges indefinitely.
	// Keep the allocated capacity for the next refresh to avoid allocator
	// churn in this long-running daemon.
	sv->hop2_count = 0;

	QRY_Mesh_ParsePingStatusPayload(sv, data + 11, (size_t)(len - 11));
}

//==============================================

void QRY_Frame(void)
{
	QRY_FL_CheckVarsModified();		// check if "masters_filter_servers" variable changed
	QRY_CheckMastersModified();		// check is "masters" variable changed
	QRY_QueryMasters();				// request time to time server list from masters
	QRY_HeartbeatMasters();			// send heartbeat to masters time to time
	QRY_SV_PingServers();			// ping time to time normal qw servers
	QRY_Mesh_QueryPeers();			// probe/re-probe servers for mesh (P2P) capability
}

//==============================================

void QRY_Init(void)
{
	masters_query		= Cvar_Get("masters_query",		"1", 0);
	masters_heartbeat	= Cvar_Get("masters_heartbeat",	"1", 0);
	masters_list		= Cvar_Get("masters",			QW_DEFAULT_MASTER_SERVERS, 0);
	masters_filter_servers = Cvar_Get("masters_filter_servers",	QW_DEFAULT_SV_FILTER, 0);

	mesh_enable			= Cvar_Get("mesh_enable",			"1",	0);
	mesh_query_interval	= Cvar_Get("mesh_query_interval",	"300",	0);
	mesh_probe_interval	= Cvar_Get("mesh_probe_interval",	"600",	0);

	Cmd_AddCommand("svlist", QRY_Cmd_SvList_f);
	Cmd_AddCommand("heartbeat", QRY_Cmd_Heartbeat_f);

	// clear filters
	QRY_FL_Init();
	// clear masters
	QRY_MastersInit();
}
