/*
	peer.c
*/

#include "qwfwd.h"

peer_t *peers = NULL;
static int userid = 0;

static int GetGlobalProbeSocketsOpen(void) {
	int count = 0;
	peer_t *p;
	for (p = peers; p; p = p->next) {
		if (p->ps == ps_pingprobe) {
			int i;
			for (i = 0; i < p->num_probes; i++) {
				if (p->probes[i].s != INVALID_SOCKET)
					count++;
			}
		}
	}
	return count;
}

#define MAX_TOTAL_PROBE_SOCKETS 64

// Records which peer (and which of its probe sockets, if any) owns each entry
// of the pollfd array, so readiness can be handed back to the owner by pointer
// instead of by array position. See FWD_network_update().
typedef struct {
	peer_t  *peer;
	probe_t *probe; // NULL when the entry is the peer's main socket
	qbool    alt;   // entry is the peer's multipath standby socket (alt_s)
} pfd_owner_t;

// Both are complete connectionless packets, including the 0xffffffff
// out-of-band header the receiver checks before parsing the command.
static const char probe_payload_qw[] = {0xff, 0xff, 0xff, 0xff, 'p', 'i', 'n', 'g', '\n'};
static const char probe_payload_gen[] = {0xff, 0xff, 0xff, 0xff, A2A_PING, 0};

// Probes must retransmit exactly what they first sent, so both send sites take
// the payload from here.
static void FWD_ProbePayload(const peer_t *p, const void **payload, int *payload_len)
{
	if (p->proto == pr_qw) {
		*payload = probe_payload_qw;
		*payload_len = sizeof(probe_payload_qw);
	} else {
		*payload = probe_payload_gen;
		*payload_len = sizeof(probe_payload_gen);
	}
}

cvar_t *sv_pathprobe_enable;
cvar_t *sv_pathprobe_count;
cvar_t *sv_pathprobe_delay;
cvar_t *multipath_enable;
cvar_t *multipath_switch_ms;
cvar_t *multipath_notify;
cvar_t *multipath_backup_tol;

// Multipath data plane: client->server goes out p->s only (duplicating would
// make the server flip the client address on every packet), alt_s is a hot
// standby source port (pathprobe runner-up). Both are health-pinged; on switch
// mvdsv remaps the address through qport. Server->client is accepted from both
// sockets so in-flight packets to the old port are not lost.
// ponytail: 2 paths, 1 ping/s, EWMA rtt + miss count; jitter/loss% scoring if it flaps
void FWD_mp_close_alt(peer_t *p)
{
	if (p->alt_s != INVALID_SOCKET && p->alt_s != p->s)
		closesocket(p->alt_s);
	p->alt_s = INVALID_SOCKET;
}

static void FWD_mp_switch(peer_t *p, double now, const char *why)
{
	int s = p->s, m = p->mp_miss[0];
	unsigned int l = p->mp_lost[0];
	double t = p->mp_rtt[0];
	struct sockaddr_in to = p->to;

	Sys_Printf("peer %s:%d multipath switch (%s) %.0fms -> %.0fms\n", inet_ntoa(p->from.sin_addr),
		(int)ntohs(p->from.sin_port), why, p->mp_rtt[0], p->mp_rtt[1]);
	// tell the player: OOB print from our address shows up in the client console; empty cvar = silent
	if (multipath_notify->string[0])
		Netchan_OutOfBandPrint(net_socket, &p->from, "%c%s &c0f0(%s)&r\n", A2C_PRINT, multipath_notify->string, why);
	p->s = p->alt_s;
	p->alt_s = s;
	p->to = p->alt_to;
	p->alt_to = to;
	p->mp_lost[0] = p->mp_lost[1];
	p->mp_lost[1] = l;
	p->mp_rtt[0] = p->mp_rtt[1];
	p->mp_rtt[1] = t;
	p->mp_miss[0] = p->mp_miss[1];
	p->mp_miss[1] = m;
	p->mp_acked[0] = p->mp_acked[1] = false;
	p->mp_wins = 0;
	p->mp_switch_at = p->mp_rx_at = p->mp_data_at = now;
	// new primary must prove it streams before silence can fire again
	p->mp_rx_rate = p->mp_rx_count = 0;
	p->mp_verify_at = 0;
}

static int FWD_mp_bits(unsigned int v)
{
	int n = 0;
	for (; v; v &= v - 1)
		n++;
	return n;
}

// Prefer a mesh qwfwd as backup: a different machine and network, so it
// survives what kills our own route. Retried every 5 s while we have none,
// since the mesh may still be settling when the player connects.
static void FWD_mp_pick_relay(peer_t *p, double now)
{
	struct sockaddr_in relay;
	int cost;
	char a[64], b[MAX_INFO_STRING];

	if (p->ps != ps_connected || p->relay || p->mp_no_relay || p->proto != pr_qw ||
		!multipath_enable->integer || now - p->mp_relay_at < 5.0)
		return;
	p->mp_relay_at = now;

	// next hop is another qwfwd: it matches peers by ip:port, a relay would orphan us there
	Info_ValueForKey(p->userinfo, QWFWD_PRX_KEY, b, sizeof(b));
	if (b[0])
		return;
	// player asked for no backup (0) or same-proxy only (1)
	Info_ValueForKey(p->userinfo, "multipath", b, sizeof(b));
	if (b[0] && atoi(b) < 2)
		return;

	// already on/with a relay, or on the backup: leave it alone
	if (!NET_CompareAddress(&p->to, &p->srv) ||
		(p->alt_s != INVALID_SOCKET && !NET_CompareAddress(&p->alt_to, &p->srv)))
		return;
	if (!QRY_Mesh_BestRelay(&p->srv, &relay, &cost))
		return;
	// expected ping within multipath_backup_tol of ours (unknown ping: take it)
	if (p->mp_rtt[0] > 0 && cost > p->mp_rtt[0] + bound(0, multipath_backup_tol->integer, 500))
		return;
	if (p->alt_s == INVALID_SOCKET && (p->alt_s = NET_UDP_OpenSocket(NULL, 0, false)) == INVALID_SOCKET)
		return;

	p->alt_to = relay;
	p->mp_rtt[1] = cost;
	p->mp_miss[1] = p->mp_lost[1] = p->mp_wins = 0;
	p->mp_acked[1] = false;
	Netchan_OutOfBandPrint(p->alt_s, &p->alt_to, "meshrelay %s\n", NET_AdrToString(&p->srv, a, sizeof(a)));
	Sys_Printf("peer %s:%d backup route via mesh qwfwd %s (~%d ms)\n", inet_ntoa(p->from.sin_addr),
		(int)ntohs(p->from.sin_port), NET_AdrToString(&relay, b, sizeof(b)), cost);
}

static void FWD_mp_tick(peer_t *p)
{
	double now = Sys_DoubleTime();
	char srv[64];
	int i;

	if (p->alt_s == INVALID_SOCKET || p->ps != ps_connected)
		return;

	// runtime kill switch: drop the standby, stay on the current path
	if (!multipath_enable->integer) {
		FWD_mp_close_alt(p);
		return;
	}

	// in game client and server both stream every frame: client still talking but server
	// silent for 500ms means the path died. Loading/downloading = client quiet too, no switch.
	// signon: client streams but server only answers when it has data, so also require the
	// server to have been streaming (>= 20 pps last second; in game it is sv fps, ~77).
	// A map change also stalls the server, so silence only arms a check: ping both paths and
	// switch if alt_s answers while s stays mute. Stalled server answers neither; s answering
	// (any packet counts) means the path is fine.
	if (p->mp_verify_at) {
		if (p->mp_rx_at > p->mp_verify_at || now - p->mp_verify_at > 1.0)
			p->mp_verify_at = 0;
		else if (p->mp_vack)
			FWD_mp_switch(p, now, "silence");
	} else if (p->mp_rx_rate >= 20 && now - p->mp_tx_at < 0.1 && now - p->mp_rx_at > 0.5 &&
		!p->mp_miss[1] && now - p->mp_switch_at > 1.0) {
		p->mp_verify_at = now;
		p->mp_vack = false;
		Netchan_OutOfBandPrint(p->s, &p->to, "%c\n", A2A_PING);
		Netchan_OutOfBandPrint(p->alt_s, &p->alt_to, "%c\n", A2A_PING);
	}

	// rollback: the new path answers pings but carries no game data (e.g. the
	// server refused the address change). Go back and drop the backup for good.
	if (p->mp_switch_at && p->mp_data_at <= p->mp_switch_at && now - p->mp_switch_at > 1.5 &&
		now - p->mp_tx_at < 0.1) {
		FWD_mp_switch(p, now, "rollback");
		FWD_mp_close_alt(p);
		p->mp_no_relay = true; // the server does not take relayed sessions
		return;
	}

	if (now - p->mp_ping_at < 1.0)
		return;

	p->mp_rx_rate = p->mp_rx_count;
	p->mp_rx_count = 0;

	for (i = 0; p->mp_ping_at && i < 2; i++) {
		p->mp_miss[i] = p->mp_acked[i] ? 0 : p->mp_miss[i] + 1;
		p->mp_lost[i] = (p->mp_lost[i] << 1) | !p->mp_acked[i];
	}

	p->mp_wins = (!p->mp_miss[1] && p->mp_rtt[1] + bound(1, multipath_switch_ms->integer, 200) < p->mp_rtt[0]) ? p->mp_wins + 1 : 0;

	// primary dead (3 pings) and alt alive, or alt faster 3 ticks in a row outside 10s cooldown
	// partial loss: 3+ of the last 10 health pings lost while the backup lost none
	// and pings close to the old route (multipath_backup_tol)
	if (p->mp_miss[0] >= 3 && !p->mp_miss[1])
		FWD_mp_switch(p, now, "loss");
	else if (FWD_mp_bits(p->mp_lost[0] & 0x3ff) >= 3 && !(p->mp_lost[1] & 0x3ff) &&
		p->mp_rtt[1] <= p->mp_rtt[0] + bound(0, multipath_backup_tol->integer, 500) && now - p->mp_switch_at > 10.0)
		FWD_mp_switch(p, now, "loss");
	else if (p->mp_wins >= 3 && now - p->mp_switch_at > 10.0)
		FWD_mp_switch(p, now, "rtt");

	p->mp_ping_at = now;
	p->mp_acked[0] = p->mp_acked[1] = false;
	NET_AdrToString(&p->srv, srv, sizeof(srv));
	// (re)register the session on the mesh relay; cheap, survives a relay restart
	if (!NET_CompareAddress(&p->alt_to, &p->srv))
		Netchan_OutOfBandPrint(p->alt_s, &p->alt_to, "meshrelay %s\n", srv);
	if (!NET_CompareAddress(&p->to, &p->srv))
		Netchan_OutOfBandPrint(p->s, &p->to, "meshrelay %s\n", srv);
	Netchan_OutOfBandPrint(p->s, &p->to, "%c\n", A2A_PING);
	Netchan_OutOfBandPrint(p->alt_s, &p->alt_to, "%c\n", A2A_PING);
}

static void FWD_mp_ack(peer_t *p, int idx)
{
	double ms = (Sys_DoubleTime() - p->mp_ping_at) * 1000.0;
	if (p->mp_acked[idx] || ms > 1000.0)
		return; // late or duplicate ack
	p->mp_acked[idx] = true;
	if (p->mp_miss[idx])
		return; // after a miss this may be the previous ping's ack: liveness only, no rtt
	p->mp_rtt[idx] = p->mp_rtt[idx] ? p->mp_rtt[idx] * 0.75 + ms * 0.25 : ms;
}


// read everything pending on one remote-facing socket, idx 0 = p->s, 1 = p->alt_s
static void FWD_read_remote(peer_t *p, int sock, int idx)
{
	for (;;) {
		if (!NET_GetPacket(sock, &net_message))
			break;

		// check for bans.
		if (SV_IsBanned(&net_from))
			continue;

		// we should check is this packet from remote server, this may be some
		// evil packet from haxors...
		if (!NET_CompareAddress(idx ? &p->alt_to : &p->to, &net_from))
			continue;

		// mesh relay for another qwfwd: everything goes back untouched
		if (p->relay) {
			NET_SendPacket(net_socket, net_message.cursize, net_message.data, &p->from);
			continue;
		}

		if (idx == 0 && !(net_message.cursize == 1 && net_message.data[0] == A2A_ACK))
			p->mp_data_at = Sys_DoubleTime();

		if (idx == 0) {
			p->mp_rx_at = Sys_DoubleTime();
			p->mp_rx_count++;
		}

		if (net_message.cursize == 1 && net_message.data[0] == A2A_ACK) {
			// ponytail: ACK carries no id, a late health-ping ack could count; window is one RTT
			if (idx == 1 && p->mp_verify_at)
				p->mp_vack = true;
			if (p->alt_s != INVALID_SOCKET)
				FWD_mp_ack(p, idx);
			continue;
		}

		MSG_BeginReading();
		if (MSG_ReadLong() == -1) {
			if (MSG_BadRead())
				continue;

			if (!CL_ConnectionlessPacket(p))
				continue; // seems we do not need forward it

			NET_SendPacket(net_socket, net_message.cursize, net_message.data, &p->from);
			continue;
		}

		if (!p->connect_pending && p->ps >= ps_connected)
			NET_SendPacket(net_socket, net_message.cursize, net_message.data, &p->from);
	}
}

// "meshrelay <ip:port>" from another mesh qwfwd: carry one of its sessions to
// that server as a hot backup route. No handshake here, the server already
// knows the player (qport) and moves it only if it trusts us (sv_proxy_migrate).
void SVC_MeshRelay(void)
{
	char host[64], *colon;
	struct sockaddr_in to = {0};
	peer_t *p;

	if (!multipath_enable->integer || !QRY_Mesh_IsPeer(&net_from) || Cmd_Argc() != 2)
		return;
	strlcpy(host, Cmd_Argv(1), sizeof(host));
	if (!(colon = strchr(host, ':')))
		return;
	*colon = 0;
	// numeric only: a mesh peer never makes us resolve names
	if (!NET_ParseIPv4(host, &to.sin_addr))
		return;
	to.sin_family = AF_INET;
	to.sin_port = htons((unsigned short)atoi(colon + 1));

	p = FWD_peer_by_addr(&net_from);
	if (p && !p->relay)
		return; // that address is a real player session
	if (!(p = FWD_peer_new(&to, &net_from, "\\name\\meshrelay", 0, pr_qw)))
		return;
	p->ps = ps_connected;
	p->relay = true;
}

peer_t	*FWD_peer_by_addr(struct sockaddr_in *from)
{
	peer_t *p;

	for (p = peers; p; p = p->next)
	{
		if (NET_CompareAddress(&p->from, from))
			return p;
	}

	return NULL;
}

static int parse_color(const char *userinfo, const char *key)
{
	char tmp[MAX_INFO_STRING];
	int color;

	Info_ValueForKey(userinfo, key, tmp, sizeof(tmp));
	color = atoi(tmp);

	return (color < 0) ? 0 : ((color > 16) ? 16 : color);
}

peer_t	*FWD_peer_new(struct sockaddr_in *to, struct sockaddr_in *from, const char *userinfo, int qport, protocol_t proto)
{
	peer_t *p;
	int s = INVALID_SOCKET;
	qbool new_peer = false;

	if (!SV_IsWhitelisted(to))
		return NULL;

	// check for bans.
	if (SV_IsBanned(to))
		return NULL;

	// we probably already have such peer, reuse it then
	p = FWD_peer_by_addr( from );

	// next check for NEW peer only
	if ( !p )
	{
		new_peer = true; // it will be new peer

		if (FWD_peers_count() >= maxclients->integer)
			return NULL; // we already full!

		// NOTE: socket allocated here! Do not forget free it!!!
		if ((s = NET_UDP_OpenSocket(NULL, 0, false)) == INVALID_SOCKET)
			return NULL; // out of sockets?

		p = Sys_malloc(sizeof(*p)); // alloc peer if needed
		p->alt_s = INVALID_SOCKET;
	}
	else if (p->proto == pr_q3 && proto == pr_q3 && p->ps == ps_challenge && p->qport != qport)
	{
		// A Q3 connectResponse has no qport. Give the new handshake its own UDP port.
		if ((s = NET_UDP_OpenSocket(NULL, 0, true)) == INVALID_SOCKET)
			return NULL;
		closesocket(p->s);
		p->connect = 0;
	}

	// reconnect: the standby (and a relay we may have switched to) is stale
	if (!new_peer)
		FWD_mp_close_alt(p);

	if (s != INVALID_SOCKET)
		p->s = s;
	p->from		= *from;
	p->to		= *to;
	p->srv		= *to;
	p->relay	= false;
	p->mp_no_relay	= false;
	p->mp_relay_at	= 0;
	p->mp_rtt[0]	= 0;
	p->ps		= ( !new_peer && (proto == pr_q3 || p->ps == ps_pingprobe) ) ? p->ps : ps_challenge; // do not reset state for q3 or ongoing probes in case of peer reusing
	p->qport	= qport;
	p->proto	= proto;
	strlcpy(p->userinfo, userinfo, sizeof(p->userinfo));
	Info_ValueForKey(userinfo, "name", p->name, sizeof(p->name));
	p->top          = parse_color(userinfo, "topcolor");
	p->bottom       = parse_color(userinfo, "bottomcolor");
	p->userid	= ( new_peer ) ? ++userid : p->userid; // do not bump userid in case of peer reusing

	time(&p->last);

	// link only new peer, in case of reusing it already done...
	if (new_peer)
	{
		p->next = peers;
		peers = p;
	}

	return p;
}

// free peer data, perform unlink if requested
static void FWD_peer_free(peer_t *peer, qbool unlink)
{
	int i;

	if (!peer)
		return;

	if (unlink)
	{
		peer_t *next, *prev, *current;

		prev = NULL;
		current = peers;

		for ( ; current; )
		{
			next = current->next;

			if (peer == current)
			{
				if (prev)
					prev->next = next;
				else
					peers = next;

				break;
			}

			prev = current;
			current = next;
		}
	}

	// free probes if any
	for (i = 0; i < peer->num_probes; i++) {
		if (peer->probes[i].s != INVALID_SOCKET && peer->probes[i].s != peer->s) {
			closesocket(peer->probes[i].s);
			peer->probes[i].s = INVALID_SOCKET;
		}
	}

	FWD_mp_close_alt(peer);

	// free all data related to peer
	if (peer->s) { // there should be no zero socket, it's stdin
		closesocket(peer->s);
		peer->s = INVALID_SOCKET;
	}

	Sys_free(peer);
}

static void FWD_check_timeout(void)
{
	byte msg_data[6];
	sizebuf_t msg;
	time_t cur_time;
	double d_cur_time;
	peer_t *p;

	SZ_InitEx(&msg, msg_data, sizeof(msg_data), true);

	cur_time = time(NULL);
	d_cur_time = Sys_DoubleTime();

	for (p = peers; p; p = p->next)
	{
		// this is helper for q3 to guess disconnect asap
		if (!p->connect_pending && p->proto == pr_q3)
		{
			if (cur_time - p->last > 1 && d_cur_time - p->q3_disconnect_check > 0.05 && p->ps == ps_connected)
			{
				p->q3_disconnect_check = d_cur_time;
				SZ_Clear(&msg);
				MSG_WriteLong(&msg, 0);
				MSG_WriteShort(&msg, p->qport);
				NET_SendPacket(p->s, msg.cursize, msg.data, &p->to);
			}
		}

		if (cur_time - p->last >= 15)
		{
			Sys_DPrintf("peer %s:%d timed out\n", inet_ntoa(p->from.sin_addr), (int)ntohs(p->from.sin_port));
			p->ps = ps_drop;
		}
		else if (!p->connect_pending && p->ps == ps_challenge && cur_time - p->connect > 2)
		{
			p->connect = cur_time;
			Netchan_OutOfBandPrint(p->s, &p->to, "getchallenge%s", p->proto == pr_qw ? "\n" : "");
		}
	}
}

static void FWD_check_drop(void)
{
	peer_t *p, *next;

	for (p = peers; p; p = next)
	{
		next = p->next;

		if (p->ps != ps_drop)
			continue;

		Sys_DPrintf("peer %s:%d dropped\n", inet_ntoa(p->from.sin_addr), (int)ntohs(p->from.sin_port));
		FWD_peer_free(p, true); // NOTE: 'p' is not valid after this function, so we remember 'next' before this function
	}
}

// Start probing for the best source port
void FWD_PeerStartProbing(peer_t *p) {
  int count = sv_pathprobe_count->integer;
  int i;
  const void *payload;
  int payload_len;

  if (count < 1)
    count = 1;
  if (count > MAX_PING_PROBES)
    count = MAX_PING_PROBES;

  // Close any existing probe sockets to prevent leaks on reuse
  for (i = 0; i < p->num_probes; i++) {
    if (p->probes[i].s != INVALID_SOCKET && p->probes[i].s > 0 &&
        p->probes[i].s != p->s) {
      closesocket(p->probes[i].s);
    }
  }

  // a reconnect re-probes from scratch; the old standby path is stale
  FWD_mp_close_alt(p);

  p->ps = ps_pingprobe;
  p->num_probes = 0;
  memset(p->probes, 0, sizeof(p->probes));
  for (i = 0; i < MAX_PING_PROBES; i++) {
    p->probes[i].s = INVALID_SOCKET;
  }
  p->probe_start_time = Sys_DoubleTime();

  FWD_ProbePayload(p, &payload, &payload_len);

  // Use existing socket as first probe
  if (p->s != INVALID_SOCKET) {
    // Discard whatever is already queued on it. On a reconnect this socket has
    // been carrying game traffic or replies from an earlier probe. Packets
    // arriving after this drain are validated by FWD_ProcessProbes().
    // NOTE: recvfrom() directly, not NET_GetPacket() - our caller
    // (SVC_DirectConnect) is still using net_message/net_from.
    char drain[MSG_BUF_SIZE];
    while (recvfrom(p->s, drain, sizeof(drain), 0, NULL, NULL) >= 0)
      ;

    p->probes[0].s = p->s;
    p->probes[0].send_time = Sys_DoubleTime();
    p->probes[0].rtt = -1;
    p->probes[0].samples_sent = 1;
    p->num_probes++;
    NET_SendPacket(p->s, payload_len, payload, &p->to);
  }

  // Create additional sockets
  for (i = p->num_probes; i < count; i++) {
    if (GetGlobalProbeSocketsOpen() >= MAX_TOTAL_PROBE_SOCKETS) {
      Sys_DPrintf(
          "Global probe socket limit reached (%d), skipping probe socket\n",
          MAX_TOTAL_PROBE_SOCKETS);
      break;
    }

    int s = NET_UDP_OpenSocket(NULL, 0, false);
    if (s != INVALID_SOCKET) {
      p->probes[p->num_probes].s = s;
      p->probes[p->num_probes].send_time = Sys_DoubleTime();
      p->probes[p->num_probes].rtt = -1;
      p->probes[p->num_probes].samples_sent = 1;
      p->num_probes++;
      NET_SendPacket(s, payload_len, payload, &p->to);
    }
  }

  Sys_DPrintf("Started probing %d ports for peer %s\n", p->num_probes, p->name);
}

// Check if probing is done or timed out
static void FWD_CheckProbeCompletion(peer_t *p) {
  int i;
  int best_idx = -1;
  double best_rtt = 99999.0;
  double timeout = sv_pathprobe_delay->value / 1000.0;
  qbool all_finished = true;

  if (timeout <= 0.0)
    timeout = 1.0;
  if (timeout > 10.0)
    timeout = 10.0;

  // Check if all probes are finished
  for (i = 0; i < p->num_probes; i++) {
    if (p->probes[i].samples_received < PROBE_SAMPLES_COUNT) {
      all_finished = false;
    }
  }

  // Only proceed if we timed out or all probes finished
  if (!all_finished && Sys_DoubleTime() - p->probe_start_time <= timeout)
    return;

  // Find best RTT
  for (i = 0; i < p->num_probes; i++) {
    if (p->probes[i].rtt > 0 && p->probes[i].rtt < best_rtt) {
      best_rtt = p->probes[i].rtt;
      best_idx = i;
    }
  }

  if (best_idx != -1) {
    struct sockaddr_in local_addr;
    socklen_t local_len = sizeof(local_addr);
    char port[16];
    p->s = p->probes[best_idx].s;
    if (getsockname(p->s, (struct sockaddr *)&local_addr, &local_len) == 0)
      snprintf(port, sizeof(port), "%u", (unsigned)ntohs(local_addr.sin_port));
    else
      strlcpy(port, "unknown", sizeof(port));

    Sys_DPrintf("Probe finished in %.2f ms. Source port %s: min proxy-server RTT %.2f ms (%d/%d replies, %d ports)\n",
                (Sys_DoubleTime() - p->probe_start_time) * 1000.0,
                port, best_rtt * 1000.0,
                p->probes[best_idx].samples_received, PROBE_SAMPLES_COUNT,
                p->num_probes);

    // Notify client about the best ping found
    if (p->proto == pr_qw) {
      Netchan_OutOfBandPrint(net_socket, &p->from,
                             "%c[qwfwd] Source port %s: min proxy-server RTT %.2f ms (%d/%d replies, %d ports)\n", A2C_PRINT,
                             port, best_rtt * 1000.0,
                             p->probes[best_idx].samples_received,
                             PROBE_SAMPLES_COUNT, p->num_probes);
    } else {
      Netchan_OutOfBandPrint(net_socket, &p->from,
                             "print\n[qwfwd] Source port %s: min proxy-server RTT %.2f ms (%d/%d replies, %d ports)\n",
                             port, best_rtt * 1000.0,
                             p->probes[best_idx].samples_received,
                             PROBE_SAMPLES_COUNT, p->num_probes);
    }

  } else {
    Sys_DPrintf("Probe finished. No reply, using default.\n");
    // Keep the original socket, including if no probe socket was available.
  }

  // Multipath: keep the runner-up as hot standby. Not when the next hop is
  // another qwfwd: it matches peers by full ip:port, not qport, so a switch
  // would orphan us there.
  // Player choice via userinfo (no client change, plain setinfo):
  // "multipath 0" = no backup, "multipath 1" = same-proxy port only, unset/2 = mesh too.
  char mp_mode[16];
  Info_ValueForKey(p->userinfo, "multipath", mp_mode, sizeof(mp_mode));
  if (best_idx != -1 && multipath_enable->integer && (!mp_mode[0] || atoi(mp_mode))) {
    char next_hop[MAX_INFO_STRING];
    int alt_idx = -1;
    double alt_rtt = 99999.0;

    Info_ValueForKey(p->userinfo, QWFWD_PRX_KEY, next_hop, sizeof(next_hop));
    for (i = 0; !next_hop[0] && i < p->num_probes; i++) {
      if (i != best_idx && p->probes[i].rtt > 0 && p->probes[i].rtt < alt_rtt) {
        alt_rtt = p->probes[i].rtt;
        alt_idx = i;
      }
    }
    // runner-up port as the first backup; FWD_mp_pick_relay upgrades it to a
    // mesh qwfwd as soon as one is known (right away, or later in the game)
    p->alt_to = p->to;
    p->mp_lost[0] = p->mp_lost[1] = 0;
    p->mp_data_at = p->mp_relay_at = 0;
    p->mp_no_relay = next_hop[0] || atoi(mp_mode) == 1;
    p->mp_rtt[0] = best_rtt * 1000.0;
    p->mp_rtt[1] = alt_rtt * 1000.0;
    p->mp_ping_at = p->mp_switch_at = p->mp_rx_at = p->mp_tx_at = 0;
    p->mp_miss[0] = p->mp_miss[1] = p->mp_wins = p->mp_rx_count = p->mp_rx_rate = 0;
    p->mp_verify_at = 0;
    if (alt_idx != -1)
      p->alt_s = p->probes[alt_idx].s;
  }

  // Close other sockets
  for (i = 0; i < p->num_probes; i++) {
    if (p->probes[i].s != p->s && p->probes[i].s != p->alt_s && p->probes[i].s != INVALID_SOCKET) {
      closesocket(p->probes[i].s);
      p->probes[i].s = INVALID_SOCKET;
    }
  }
  // s and alt_s are now owned by the peer fields; s and alt_s swap on a
  // multipath switch, so stale copies here would be closed twice on free/reprobe
  for (i = 0; i < p->num_probes; i++)
    p->probes[i].s = INVALID_SOCKET;

  // Send connection packet to client now that we are ready
  if (p->proto == pr_qw) {
    Netchan_OutOfBandPrint(net_socket, &p->from, "%c", S2C_CONNECTION);
  } else {
    Netchan_OutOfBandPrint(net_socket, &p->from, "connectResponse");
  }

  p->ps = ps_connecting;
  p->connect = 0;
}

// Process incoming packets on probe sockets.
// Readiness comes from probes[i].revents, which FWD_network_update() copied out
// of the pollfd array right after qpoll(). Do NOT index a pollfd array by
// position here: the peer list can change while we are draining net_socket.
static void FWD_ProcessProbes(peer_t *p) {
  int i;
  const void *payload;
  int payload_len;

  FWD_ProbePayload(p, &payload, &payload_len);

  for (i = 0; i < p->num_probes; i++) {
    if (p->probes[i].s != INVALID_SOCKET) {
      if (p->probes[i].revents & POLLIN) {
        qbool received = false;
        // Drain this batch before sending the next probe, so queued duplicate
        // ACKs cannot be timed against that next probe's send timestamp.
        while (NET_GetPacket(p->probes[i].s, &net_message)) {
          if (!received &&
              p->probes[i].samples_received < p->probes[i].samples_sent &&
              NET_CompareAddress(&p->to, &net_from) &&
              net_message.cursize == 1 && net_message.data[0] == A2A_ACK) {
            double rtt = Sys_DoubleTime() - p->probes[i].send_time;

            received = true;
            p->probes[i].samples_received++;

            if (p->probes[i].rtt == -1 || rtt < p->probes[i].rtt) {
              p->probes[i].rtt = rtt;
            }
            Sys_DPrintf("Pathprobe reply on socket %d, sample %d, RTT %.2f ms\n",
                        p->probes[i].s, p->probes[i].samples_received,
                        rtt * 1000.0);
          }
        }
        if (received && p->probes[i].samples_sent < PROBE_SAMPLES_COUNT) {
          p->probes[i].samples_sent++;
          p->probes[i].send_time = Sys_DoubleTime();
          NET_SendPacket(p->probes[i].s, payload_len, payload, &p->to);
        }
      }
    }
  }
}

#define STUN_HEADER_SIZE 20

/*
=================
FWD_StunBindingPacket

Answers a STUN Binding request (RFC 8489) with the sender's address as seen by
the proxy (XOR-MAPPED-ADDRESS). Browsers cannot send raw UDP, so this is the
only way a web page can measure RTT to the proxy: list it as an ICE server
(stun:<ip>:<port>) and time how long the server-reflexive candidate takes to
arrive. No QW connection is made.
Returns true if the packet was STUN and must not be parsed as game traffic.
=================
*/
static qbool FWD_StunBindingPacket(void)
{
	static const byte magic_cookie[4] = { 0x21, 0x12, 0xA4, 0x42 };
	byte *data = net_message.data;
	byte *port = (byte *) &net_from.sin_port; // already network byte order
	byte *ip = (byte *) &net_from.sin_addr.s_addr; // already network byte order
	byte response[STUN_HEADER_SIZE + 12];
	int len = net_message.cursize;
	int pos, attr_len, i;

	if (len < STUN_HEADER_SIZE || memcmp(data + 4, magic_cookie, 4)) {
		return false;
	}

	// only a Binding request whose length field matches the datagram
	if (data[0] != 0x00 || data[1] != 0x01 || ((data[2] << 8) | data[3]) != len - STUN_HEADER_SIZE) {
		return true;
	}

	// attributes below 0x8000 are comprehension-required and we know none
	pos = STUN_HEADER_SIZE;
	while (pos + 4 <= len) {
		if (data[pos] < 0x80) {
			return true;
		}
		attr_len = (data[pos + 2] << 8) | data[pos + 3];
		pos += 4 + ((attr_len + 3) & ~3); // values are padded to 4 bytes
	}
	if (pos != len) {
		return true;
	}

	// cookie and transaction id echo back
	memcpy(response, data, STUN_HEADER_SIZE);
	response[0] = 0x01; // Binding success response
	response[1] = 0x01;
	response[2] = 0;
	response[3] = 12;
	response[20] = 0x00; // XOR-MAPPED-ADDRESS
	response[21] = 0x20;
	response[22] = 0;
	response[23] = 8;
	response[24] = 0;
	response[25] = 0x01; // IPv4
	response[26] = port[0] ^ magic_cookie[0];
	response[27] = port[1] ^ magic_cookie[1];
	for (i = 0; i < 4; i++) {
		response[28 + i] = ip[i] ^ magic_cookie[i];
	}

	NET_SendPacket(net_from_socket, sizeof(response), response, &net_from);
	return true;
}

static void FWD_network_update(void) {
  net_pollfd_t *pfds = NULL;
  pfd_owner_t *owners = NULL;
  int nfds = 0;
  int max_fds = 2; // net + stdin
  int retval;
  int net_idx = -1;
#ifndef _WIN32
  int stdin_idx = -1;
#endif
  peer_t *p;
  int i;

  // Calculate max FDs needed, and clear stale readiness from the previous
  // iteration so a peer we do not poll this time never looks ready.
  for (p = peers; p; p = p->next) {
    p->revents = 0;
    for (i = 0; i < p->num_probes; i++) {
      p->probes[i].revents = 0;
    }

    p->alt_revents = 0;

    if (p->ps == ps_pingprobe) {
      max_fds += p->num_probes;
    } else {
      max_fds += (p->alt_s != INVALID_SOCKET) ? 2 : 1;
    }
  }

  pfds = Sys_malloc(sizeof(net_pollfd_t) * max_fds);
  // owners[i] records who owns pfds[i]. Sys_malloc() zeroes, so entries we
  // never fill in (net_socket, stdin) stay { NULL, NULL } and are skipped.
  owners = Sys_malloc(sizeof(pfd_owner_t) * max_fds);

  // select on main server socket
  pfds[nfds].fd = net_socket;
  pfds[nfds].events = POLLIN;
  pfds[nfds].revents = 0;
  net_idx = nfds++;

  for (p = peers; p; p = p->next) {
    // select on peers sockets
    if (p->ps == ps_pingprobe) {
      for (i = 0; i < p->num_probes && nfds < max_fds; i++) {
        if (p->probes[i].s != INVALID_SOCKET) {
          pfds[nfds].fd = p->probes[i].s;
          pfds[nfds].events = POLLIN;
          pfds[nfds].revents = 0;
          owners[nfds].peer = p;
          owners[nfds].probe = &p->probes[i];
          nfds++;
        }
      }
    } else if (nfds < max_fds) {
      pfds[nfds].fd = p->s;
      pfds[nfds].events = POLLIN;
      pfds[nfds].revents = 0;
      owners[nfds].peer = p;
      owners[nfds].probe = NULL;
      nfds++;
      if (p->alt_s != INVALID_SOCKET && nfds < max_fds) {
        pfds[nfds].fd = p->alt_s;
        pfds[nfds].events = POLLIN;
        pfds[nfds].revents = 0;
        owners[nfds].peer = p;
        owners[nfds].probe = NULL;
        owners[nfds].alt = true;
        nfds++;
      }
    }
  }

// if not DLL - read stdin
#ifndef APP_DLL
#ifndef _WIN32
  // try read stdin only if connected to a terminal.
  if (isatty(STDIN) && isatty(STDOUT) && nfds < max_fds) {
    pfds[nfds].fd = STDIN;
    pfds[nfds].events = POLLIN;
    pfds[nfds].revents = 0;
    stdin_idx = nfds++;
  }
#endif // _WIN32
#endif

retry:
  retval = qpoll(pfds, nfds, 100);
  if (retval < 0) {
    if (errno == EINTR) {
      goto retry;
    }
    perror("poll");
    Sys_free(owners);
    Sys_free(pfds);
    return;
  }

  // Copy readiness out of pfds and onto the owning peer/probe *now*, while the
  // pfds <-> peers mapping is still valid. Draining net_socket below can create
  // new peers (SVC_DirectConnect() -> FWD_peer_new() prepends to 'peers') and
  // can move an existing peer into ps_pingprobe with a different socket count,
  // so any later walk of 'peers' no longer lines up with pfds positionally.
  for (i = 0; i < nfds; i++) {
    if (owners[i].probe) {
      owners[i].probe->revents = pfds[i].revents;
    } else if (owners[i].alt) {
      owners[i].peer->alt_revents = pfds[i].revents;
    } else if (owners[i].peer) {
      owners[i].peer->revents = pfds[i].revents;
    }
  }

  // read console input.
  // NOTE: we do not do that if we are in DLL mode...
  {
    fd_set rfds;
    FD_ZERO(&rfds);
#ifdef _WIN32
    // STDIN gets no pollfd entry on Windows: WSAPoll() handles sockets only.
    // The Windows half of Sys_ReadSTDIN() polls the console with
    // _kbhit()/_getch() and ignores the fd_set, so it has to be called every
    // iteration or console commands never get read.
    Sys_ReadSTDIN(&ps, rfds);
#else
    if (stdin_idx != -1 && (pfds[stdin_idx].revents & POLLIN)) {
      FD_SET(STDIN, &rfds);
      Sys_ReadSTDIN(&ps, rfds);
    }
#endif
  }

  // if we have input packet on main server/proxy socket, then read it
  if (net_idx != -1 && (pfds[net_idx].revents & POLLIN)) {
    qbool connectionless;
    int cnt;

    // read it
    for (;;) {
      if (!NET_GetPacket(net_socket, &net_message))
        break;

      // check for bans.
      if (SV_IsBanned(&net_from))
        continue;

      // mesh relay session: forward untouched (health pings included, they
      // must reach the server to measure the full path); refresh requests stay here
      if ((p = FWD_peer_by_addr(&net_from)) && p->relay) {
        if (!(net_message.cursize > 13 && *(int *)net_message.data == -1 &&
              !strncmp((char *)net_message.data + 4, "meshrelay", 9)))
          NET_SendPacket(p->s, net_message.cursize, net_message.data, &p->to);
        time(&p->last);
        continue;
      }

      if (net_message.cursize == 1 && net_message.data[0] == A2A_ACK) {
        QRY_SV_PingReply();

        continue;
      }

      // answer STUN Binding requests (browser RTT probes) without forwarding them
      if (FWD_StunBindingPacket())
        continue;

      MSG_BeginReading();
      connectionless = (MSG_ReadLong() == -1);

      if (connectionless) {
        if (MSG_BadRead())
          continue;

        if (!SV_ConnectionlessPacket())
          continue; // seems we do not need forward it
      }

      // search in peers
      for (p = peers; p; p = p->next) {
        // we have this peer already, so forward/send packet to remote server
        if (NET_CompareAddress(&p->from, &net_from))
          break;
      }

      if (!p)
        continue;

      // forward data to the server/proxy
      if (p->ps >= ps_connected) {
        cnt = p->connect_pending ? 0 : 1;

        // A QW client packet starts with two sequence numbers and a little-endian qport.
        if (p->proto == pr_qw && !connectionless && net_message.cursize > 10 &&
            net_message.data[10] == clc_stringcmd && !strcmp((char *)net_message.data + 11, "drop")) {
          unsigned short qport = net_message.data[8] | (net_message.data[9] << 8);
          if (qport != (unsigned short)p->qport)
            continue;

          p->ps = ps_drop;
          SVC_CancelConnectForRoute(p);
          cnt = 3; // Repeat the drop in case of packet loss.
        }

        for (; cnt > 0; cnt--)
          NET_SendPacket(p->s, net_message.cursize, net_message.data, &p->to);
        if (!connectionless && !p->connect_pending)
          p->mp_tx_at = Sys_DoubleTime();
      }

      // Keep the old connection alive while a new destination resolves.
      time(&p->last);
    }
  }

  // now lets check peers sockets, perhaps we have input packets too.
  // NOTE: readiness is read from p->revents / p->probes[].revents, never by
  // indexing pfds here - 'peers' may have grown since pfds was built.
  // A peer created during this iteration has revents == 0 (Sys_malloc() zeroes)
  // and is simply picked up on the next pass.
  for (p = peers; p; p = p->next) {
    if (p->ps == ps_pingprobe) {
      FWD_ProcessProbes(p);

      // Check completion again in case we got last packet or timed out
      FWD_CheckProbeCompletion(p);
      continue; // Skip normal processing for this peer
    }

    // revents belong to the sockets polled this pass; a switch inside
    // FWD_mp_tick happens after both reads, so they still line up
    if (p->ps == ps_drop)
      continue;
    if (p->revents & POLLIN)
      FWD_read_remote(p, p->s, 0);
    if (p->alt_s != INVALID_SOCKET && (p->alt_revents & POLLIN))
      FWD_read_remote(p, p->alt_s, 1);
    FWD_mp_pick_relay(p, Sys_DoubleTime());
    FWD_mp_tick(p);

    if (!p->connect_pending && p->ps == ps_connecting) {
      // send challenge time to time
      if (time(NULL) - p->connect > 2) {
        p->connect = time(NULL);
        Netchan_OutOfBandPrint(p->s, &p->to, "getchallenge%s",
                               p->proto == pr_qw ? "\n" : "");
      }
    }
  } // for (p = peers; p; p = p->next)

  Sys_free(owners);
  Sys_free(pfds);
}

int FWD_peers_count(void)
{
	int cnt;
	peer_t *p;

	for (cnt = 0, p = peers; p; p = p->next)
	{
		cnt++;
	}

	return cnt;
}

//======================================================

static void FWD_Cmd_ClList_f(void)
{
	peer_t *p;
	char ipport1[] = "xxx.xxx.xxx.xxx:xxxxx";
	char ipport2[] = "xxx.xxx.xxx.xxx:xxxxx";
	int idx;
	time_t current = time(NULL);

	Sys_Printf("=== client list ===\n");
	Sys_Printf("##id## %-*s %-*s time name\n", sizeof(ipport1)-1, "address from", sizeof(ipport2)-1, "address to");
	Sys_Printf("-----------------------------------------------------------------------\n");

	for (idx = 1, p = peers; p; p = p->next, idx++)
	{
		Sys_Printf("%6d %-*s %-*s %4d %s\n",
			p->userid,
			sizeof(ipport1)-1, NET_AdrToString(&p->from, ipport1, sizeof(ipport1)),
			sizeof(ipport2)-1, NET_AdrToString(&p->to,   ipport2, sizeof(ipport2)),
			(int)(current - p->connect)/60, p->name);
	}

	Sys_Printf("-----------------------------------------------------------------------\n");
	Sys_Printf("%d clients\n", idx-1);
}

//======================================================

void FWD_update_peers(void)
{
	FWD_network_update();
	FWD_check_timeout();
	FWD_check_drop();
}

//======================================================

void FWD_Init(void)
{
	peers = NULL;
	userid = 0;

	Cmd_AddCommand("cllist", FWD_Cmd_ClList_f);
}
