/*
	peer.c
*/

#include "qwfwd.h"

peer_t *peers = NULL;
static int userid = 0;

static int probe_sockets_open = 0;
#define MAX_TOTAL_PROBE_SOCKETS 64

static const char probe_payload_qw[]  = { 0xff, 0xff, 0xff, 0xff, 'p', 'i', 'n', 'g', '\n' };
static const char probe_payload_gen[] = { A2A_PING, 0 };

cvar_t *sv_pathprobe_enable;
cvar_t *sv_pathprobe_count;
cvar_t *sv_pathprobe_delay;

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

peer_t	*FWD_peer_new(const char *remote_host, int remote_port, struct sockaddr_in *from, const char *userinfo, int qport, protocol_t proto, qbool link)
{
	peer_t *p;
	struct sockaddr_in to;
	int s = INVALID_SOCKET;
	qbool new_peer = false;

	if (!NET_GetSockAddrIn_ByHostAndPort(&to, remote_host, remote_port))
		return NULL; // failed to resolve host name?

	if (!SV_IsWhitelisted(&to))
		return NULL;

	// check for bans.
	if (SV_IsBanned(&to))
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
	}

	p->s		= ( new_peer ) ? s : p->s; // reuse socket in case of reusing
	p->from		= *from;
	p->to		= to;
	p->ps		= ( !new_peer && proto == pr_q3 ) ? p->ps : ps_challenge; // do not reset state for q3 in case of peer reusing
	p->qport	= qport;
	p->proto	= proto;
	strlcpy(p->userinfo, userinfo, sizeof(p->userinfo));
	Info_ValueForKey(userinfo, "name", p->name, sizeof(p->name));
	p->top          = parse_color(userinfo, "topcolor");
	p->bottom       = parse_color(userinfo, "bottomcolor");
	p->userid	= ( new_peer ) ? ++userid : p->userid; // do not bump userid in case of peer reusing

	time(&p->last);

	// link only new peer, in case of reusing it already done...
	if (new_peer && link)
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
			probe_sockets_open--;
		}
	}

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
		if (p->proto == pr_q3)
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

		if (cur_time - p->last < 15) // few seconds timeout
			continue;

		Sys_DPrintf("peer %s:%d timed out\n", inet_ntoa(p->from.sin_addr), (int)ntohs(p->from.sin_port));

		p->ps = ps_drop;
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
void FWD_PeerStartProbing(peer_t *p)
{
	int count = sv_pathprobe_count->integer;
	int i;
	const void *payload;
	int payload_len;

	if (count < 1) count = 1;
	if (count > MAX_PING_PROBES) count = MAX_PING_PROBES;

	// Close any existing probe sockets to prevent leaks on reuse
	for (i = 0; i < MAX_PING_PROBES; i++) {
		if (p->probes[i].s != INVALID_SOCKET && p->probes[i].s > 0 && p->probes[i].s != p->s) {
			closesocket(p->probes[i].s);
			probe_sockets_open--;
		}
	}

	p->ps = ps_pingprobe;
	p->num_probes = 0;
	memset(p->probes, 0, sizeof(p->probes));
	for (i = 0; i < MAX_PING_PROBES; i++) {
		p->probes[i].s = INVALID_SOCKET;
	}
	p->probe_start_time = Sys_DoubleTime();

	if (p->proto == pr_qw) {
		payload = probe_payload_qw;
		payload_len = sizeof(probe_payload_qw);
	} else {
		payload = probe_payload_gen;
		payload_len = sizeof(probe_payload_gen);
	}

	// Use existing socket as first probe
	if (p->s != INVALID_SOCKET) {
		p->probes[0].s = p->s;
		p->probes[0].send_time = Sys_DoubleTime();
		p->probes[0].rtt = -1;
		p->probes[0].samples_sent = 1;
		p->num_probes++;
		NET_SendPacket(p->s, payload_len, payload, &p->to);
	}

	// Create additional sockets
	for (i = p->num_probes; i < count; i++) {
		if (probe_sockets_open >= MAX_TOTAL_PROBE_SOCKETS) {
			Sys_DPrintf("Global probe socket limit reached (%d), skipping probe socket\n", probe_sockets_open);
			break;
		}

		int s = NET_UDP_OpenSocket(NULL, 0, false);
		if (s != INVALID_SOCKET) {
			p->probes[i].s = s;
			p->probes[i].send_time = Sys_DoubleTime();
			p->probes[i].rtt = -1;
			p->probes[i].samples_sent = 1;
			p->num_probes++;
			probe_sockets_open++;
			NET_SendPacket(s, payload_len, payload, &p->to);
		}
	}
	
	Sys_DPrintf("Started probing %d ports for peer %s\n", p->num_probes, p->name);
}

// Check if probing is done or timed out
static void FWD_CheckProbeCompletion(peer_t *p)
{
	int i;
	int best_idx = -1;
	double best_rtt = 99999.0;
	double timeout = sv_pathprobe_delay->value / 1000.0;
	qbool all_finished = true;
	int fully_sampled = 0;

	if (timeout <= 0.0) timeout = 1.0;
	if (timeout > 10.0) timeout = 10.0;

	// Check if all probes are finished
	for (i = 0; i < p->num_probes; i++) {
		if (p->probes[i].samples_received >= 2) fully_sampled++;

		if (p->probes[i].samples_received < 3) {
			all_finished = false;
		}
	}

	// Wait for at least 2 samples from everyone to filter jitter, unless timed out
	if (fully_sampled == p->num_probes)
		goto select_best; 

	// Only proceed if we timed out or all probes finished
	if (!all_finished && Sys_DoubleTime() - p->probe_start_time <= timeout)
		return;

select_best:
	// Find best RTT
	for (i = 0; i < p->num_probes; i++) {
		if (p->probes[i].rtt > 0 && p->probes[i].rtt < best_rtt) {
			best_rtt = p->probes[i].rtt;
			best_idx = i;
		}
	}
	
	if (best_idx != -1) {
		Sys_DPrintf("Probe finished in %.2f ms. Best RTT: %.2f ms (idx %d)\n", (Sys_DoubleTime() - p->probe_start_time) * 1000.0, best_rtt * 1000.0, best_idx);
		p->s = p->probes[best_idx].s;

		// Notify client about the best ping found
		if (p->proto == pr_qw) {
			Netchan_OutOfBandPrint(net_socket, &p->from, "%c[qwfwd] Best RTT: %.2f ms\n", A2C_PRINT, best_rtt * 1000.0);
		} else {
			Netchan_OutOfBandPrint(net_socket, &p->from, "print\n[qwfwd] Best RTT: %.2f ms\n", best_rtt * 1000.0);
		}

	} else {
		Sys_DPrintf("Probe finished. No reply, using default.\n");
		p->s = p->probes[0].s; // Fallback to first
	}
	
	// Close other sockets
	for (i = 0; i < p->num_probes; i++) {
		if (p->probes[i].s != p->s && p->probes[i].s != INVALID_SOCKET) {
			closesocket(p->probes[i].s);
			p->probes[i].s = INVALID_SOCKET;
			probe_sockets_open--;
		}
	}

	// Send connection packet to client now that we are ready
	if (p->proto == pr_qw) {
		Netchan_OutOfBandPrint(net_socket, &p->from, "%c", S2C_CONNECTION);
	} else {
		Netchan_OutOfBandPrint(net_socket, &p->from, "connectResponse");
	}
	
	p->ps = ps_connecting;
	p->connect = 0;
}

// Process incoming packets on probe sockets
static void FWD_ProcessProbes(peer_t *p, net_pollfd_t *pfds)
{
	int i;
	int pfd_idx = 0;
	const void *payload;
	int payload_len;

	if (p->proto == pr_qw) {
		payload = probe_payload_qw;
		payload_len = sizeof(probe_payload_qw);
	} else {
		payload = probe_payload_gen;
		payload_len = sizeof(probe_payload_gen);
	}

	for (i = 0; i < p->num_probes; i++) {
		if (p->probes[i].s != INVALID_SOCKET) {
			if (pfds[pfd_idx].revents & POLLIN) {
				if (NET_GetPacket(p->probes[i].s, &net_message)) {
					if (NET_CompareAddress(&p->to, &net_from)) {
						// Any reply from the server on the probe socket is enough to measure RTT
						double rtt = Sys_DoubleTime() - p->probes[i].send_time;

						p->probes[i].samples_received++;

						if (p->probes[i].rtt == -1 || rtt < p->probes[i].rtt) {
							p->probes[i].rtt = rtt;
							Sys_DPrintf("Pathprobe reply on socket %d, sample %d, RTT %.2f ms\n", p->probes[i].s, p->probes[i].samples_received, p->probes[i].rtt * 1000.0);
						}

						// Send next sample if needed
						if (p->probes[i].samples_sent < 3) {
							p->probes[i].samples_sent++;
							p->probes[i].send_time = Sys_DoubleTime();
							NET_SendPacket(p->probes[i].s, payload_len, payload, &p->to);
						}
					}
				}
			}
			pfd_idx++;
		}
	}
}

static void FWD_network_update(void)
{
	net_pollfd_t *pfds = NULL;
	int nfds = 0;
	int max_fds = 2; // net + stdin
	int retval;
	int net_idx = -1;
	int stdin_idx = -1;
	peer_t *p;
	int i;
	int current_pfd_idx;

	// Calculate max FDs needed
	for (p = peers; p; p = p->next) {
		if (p->ps == ps_pingprobe) {
			max_fds += p->num_probes;
		} else {
			max_fds++;
		}
	}

	pfds = Sys_malloc(sizeof(net_pollfd_t) * max_fds);

	// select on main server socket
	pfds[nfds].fd = net_socket;
	pfds[nfds].events = POLLIN;
	pfds[nfds].revents = 0;
	net_idx = nfds++;

	for (p = peers; p; p = p->next)
	{
		// select on peers sockets
		if (p->ps == ps_pingprobe) {
			for (i = 0; i < p->num_probes; i++) {
				if (p->probes[i].s != INVALID_SOCKET) {
					pfds[nfds].fd = p->probes[i].s;
					pfds[nfds].events = POLLIN;
					pfds[nfds].revents = 0;
					nfds++;
				}
			}
		} else {
			pfds[nfds].fd = p->s;
			pfds[nfds].events = POLLIN;
			pfds[nfds].revents = 0;
			nfds++;
		}
	}

// if not DLL - read stdin
#ifndef APP_DLL
	#ifndef _WIN32
	// try read stdin only if connected to a terminal.
	if (isatty(STDIN) && isatty(STDOUT))
	{
		pfds[nfds].fd = STDIN;
		pfds[nfds].events = POLLIN;
		pfds[nfds].revents = 0;
		stdin_idx = nfds++;
	}
	#endif // _WIN32
#endif

retry:
	retval = qpoll(pfds, nfds, 100);
	if (retval < 0)
	{
		if (errno == EINTR)
		{
			goto retry;
		}
		perror("poll");
		Sys_free(pfds);
		return;
	}

	// read console input.
	// NOTE: we do not do that if we are in DLL mode...
	if (stdin_idx != -1 && (pfds[stdin_idx].revents & POLLIN)) {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(STDIN, &rfds);
		Sys_ReadSTDIN(&ps, rfds);
	}

	// Handle timeouts regardless of select result
	for (p = peers; p; p = p->next) {
		if (p->ps == ps_pingprobe) {
			FWD_CheckProbeCompletion(p);
		}
	}

	if (retval <= 0) {
		Sys_free(pfds);
		return;
	}

	// if we have input packet on main server/proxy socket, then read it
	if(net_idx != -1 && (pfds[net_idx].revents & POLLIN))
	{
		qbool connectionless;
		int cnt;

		// read it
		for(;;)
		{
			if (!NET_GetPacket(net_socket, &net_message))
				break;

			// check for bans.
			if (SV_IsBanned(&net_from))
				continue;

			if (net_message.cursize == 1 && net_message.data[0] == A2A_ACK)
			{
				QRY_SV_PingReply();

				continue;
			}

			MSG_BeginReading();
			connectionless = (MSG_ReadLong() == -1);

			if (connectionless)
			{
				if (MSG_BadRead())
					continue;

				if (!SV_ConnectionlessPacket())
					continue; // seems we do not need forward it
			}

			// search in peers
			for (p = peers; p; p = p->next)
			{
				// we have this peer already, so forward/send packet to remote server
				if (NET_CompareAddress(&p->from, &net_from))
					break;
			}

			// peer was not found
			if (!p)
				continue;

			// forward data to the server/proxy
			if (p->ps >= ps_connected)
			{
				cnt = 1; // one packet by default

				// check for "drop" aka client disconnect,
				// first 10 bytes for NON connectionless packet is netchan related shit in QW
				if (p->proto == pr_qw && !connectionless && net_message.cursize > 10 && net_message.data[10] == clc_stringcmd)
				{
					if (!strcmp((char*)net_message.data + 10 + 1, "drop"))
					{
//						Sys_Printf("peer drop detected\n");
						p->ps = ps_drop; // drop peer ASAP
						cnt = 3; // send few packets due to possibile packet lost
					}
				}

				for ( ; cnt > 0; cnt--)
					NET_SendPacket(p->s, net_message.cursize, net_message.data, &p->to);
			}

			time(&p->last);
		}
	}

	// now lets check peers sockets, perhaps we have input packets too
	current_pfd_idx = 1; // skip net_socket
	for (p = peers; p; p = p->next)
	{
		if (p->ps == ps_pingprobe) {
			FWD_ProcessProbes(p, &pfds[current_pfd_idx]);
			
			// count how many we used
			for (i = 0; i < p->num_probes; i++) {
				if (p->probes[i].s != INVALID_SOCKET) current_pfd_idx++;
			}
			
			// Check completion again in case we got last packet
			FWD_CheckProbeCompletion(p);
			continue; // Skip normal processing for this peer
		}

		if (pfds[current_pfd_idx].revents & POLLIN)
		{
			// yeah, we have packet, read it then
			for (;;)
			{
				if (!NET_GetPacket(p->s, &net_message))
					break;

				// check for bans.
				if (SV_IsBanned(&net_from))
					continue;

				// we should check is this packet from remote server, this may be some evil packet from haxors...
				if (!NET_CompareAddress(&p->to, &net_from))
					continue;

				MSG_BeginReading();
				if (MSG_ReadLong() == -1)
				{
					if (MSG_BadRead())
						continue;

					if (!CL_ConnectionlessPacket(p))
						continue; // seems we do not need forward it

					NET_SendPacket(net_socket, net_message.cursize, net_message.data, &p->from);
					continue;
				}

				if (p->ps >= ps_connected)
					NET_SendPacket(net_socket, net_message.cursize, net_message.data, &p->from);

// qqshka: commented out
//				time(&p->last);

			} // for (;;)
		} // if(POLLIN)
		
		current_pfd_idx++;

		if (p->ps == ps_challenge || p->ps == ps_connecting)
		{
			// send challenge time to time
			if (time(NULL) - p->connect > 2)
			{
				p->connect = time(NULL);
				Netchan_OutOfBandPrint(p->s, &p->to, "getchallenge%s", p->proto == pr_qw ? "\n" : "");
			}
		}
	} // for (p = peers; p; p = p->next)
	
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

	sv_pathprobe_enable = Cvar_Get("sv_pathprobe_enable", "1", 0);
	sv_pathprobe_count = Cvar_Get("sv_pathprobe_count", "64", 0);
	sv_pathprobe_delay = Cvar_Get("sv_pathprobe_delay", "1000", 0);

	Cmd_AddCommand("cllist", FWD_Cmd_ClList_f);
}

