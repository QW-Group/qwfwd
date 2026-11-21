/*
	svc.c
*/

#include "qwfwd.h"

/*
=================
SVC_GetChallenge

Returns a challenge number that can be used
in a subsequent client_connect command.
We do this to prevent denial of service attacks that
flood the server with invalid connection IPs.  With a
challenge, they must give a valid IP address.
=================
*/

// MAX_CHALLENGES is made large to prevent a denial
// of service attack that could cycle all of them
// out before legitimate users connected
#define	MAX_CHALLENGES	1024

typedef struct
{
	struct sockaddr_in		adr;
	int						challenge;
	time_t					time;
	protocol_t				proto;
} challenge_t;

static challenge_t		challenges[MAX_CHALLENGES];	// to prevent invalid IPs from connecting

// find challenge for address if any
static unsigned int FindChallengeForAddr(struct sockaddr_in *addr)
{
	unsigned int i;

	for (i = 0; i < MAX_CHALLENGES; i++)
	{
		if (NET_CompareAddress(addr, &challenges[i].adr))
		{
			break; // found
		}
	}

	return i;
}

// see if the challenge is valid
static qbool CheckChallenge( int challenge )
{
	unsigned int i = FindChallengeForAddr(&net_from);

	if (i >= MAX_CHALLENGES)
	{
		Netchan_OutOfBandPrint(net_from_socket, &net_from, "%c\nNo challenge for address.\n", A2C_PRINT);
		return false;
	}

	if (challenge != challenges[i].challenge)
	{
		Netchan_OutOfBandPrint(net_from_socket, &net_from, "%c\nBad challenge.\n", A2C_PRINT);
		return false;
	}

	return true; // good!
}

static void SVC_GetChallenge ( protocol_t proto )
{
	time_t	oldestTime;
	int		i, oldest;
	char	buf[256];

	oldest = 0;
	oldestTime = 0x7fffffff;

	// see if we already have a challenge for this ip
	for (i = 0 ; i < MAX_CHALLENGES; i++)
	{
		if (NET_CompareAddress(&net_from, &challenges[i].adr))
			break;

		if (challenges[i].time < oldestTime)
		{
			oldestTime = challenges[i].time;
			oldest = i;
		}
	}

	if (i == MAX_CHALLENGES)
	{
		// overwrite the oldest
		i = oldest;
		challenges[i].challenge = (rand() << 16) ^ rand();
		challenges[i].adr		= net_from;
		challenges[i].time		= time(NULL);
	}

	// overwrite proto in any case!
	challenges[i].proto	= proto;

	if ( challenges[i].proto == pr_q3 )
	{
		peer_t *p = FWD_peer_by_addr( &net_from );
		if ( p && p->ps == ps_connected )
		{
			Sys_DPrintf("challenge q3 overwrite trick!\n");
			challenges[i].challenge = p->challenge; // use challenge from q3 server since q3 packets encrypted with it...
		}
	}

	if ( developer->integer )
	{
		Sys_DPrintf("challenge %s: %s %d\n", challenges[i].proto == pr_qw ? "qw" : "q3", NET_AdrToString(&net_from, buf, sizeof(buf)), challenges[i].challenge);
	}

	// send it back
	if ( challenges[i].proto == pr_qw )
	{
		char *over;

		snprintf(buf, sizeof(buf), "%c%i", S2C_CHALLENGE, challenges[i].challenge);

		over = buf + strlen(buf) + 1;

		Netchan_OutOfBand(net_from_socket, &net_from, over-buf, (byte*) buf);
	}
	else
	{
		Netchan_OutOfBandPrint(net_from_socket, &net_from, "challengeResponse %i", challenges[i].challenge);	
	}
}

/*
==================
SVC_DirectConnect

A connection request that did not come from the master
==================
*/

static qbool CheckProtocol( int ver, protocol_t proto )
{
	if ( proto == pr_qw )
	{
		if (ver != QW_PROTOCOL_VERSION)
		{
			Netchan_OutOfBandPrint (net_from_socket, &net_from, "%c\nServer is version " QW_VERSION ".\n", A2C_PRINT);
			Sys_DPrintf ("* rejected connect from version %i\n", ver);
			return false;
		}
	}
	else
	{
#if 0 // who care which version it is?
		if (ver != 68)
		{
			Netchan_OutOfBandPrint (net_from_socket, &net_from, "%c\nServer is version 68.\n", A2C_PRINT);
			Sys_DPrintf ("* rejected connect from version %i\n", ver);
			return false;
		}
#endif
	}

	return true;
}

static qbool CheckUserinfo( char *userinfobuf, unsigned int bufsize, char *userinfo )
{
	strlcpy (userinfobuf, userinfo, bufsize);

	// and now validate userinfo
	if ( !ValidateUserInfo( userinfobuf ) )
	{
		Netchan_OutOfBandPrint (net_from_socket, &net_from, "%c\nInvalid userinfo. Restart your qwcl\n", A2C_PRINT);
		return false;
	}

	return true;
}

#define MAX_PENDING_CONNECTS 64
#define MAX_PENDING_CONNECTS_PER_IP 8

typedef struct
{
	struct sockaddr_in from;
	int socket, port, qport, challenge;
	protocol_t proto;
	char host[MAX_PRX_HOST];
	char userinfo[MAX_INFO_STRING];
} connect_request_t;

typedef struct connect_lookup
{
	struct connect_lookup *next;
	struct sockaddr_in owner;
	char host[];
} connect_lookup_t;

typedef struct pending_connect
{
	struct pending_connect *next;
	connect_request_t request;
	connect_lookup_t *lookup;
} pending_connect_t;

static pending_connect_t *pending_connects;
static connect_lookup_t *connect_lookups;

static void SVC_FinishConnect(connect_request_t *request, struct in_addr address)
{
	struct sockaddr_in to = {0};
	peer_t *p;

	to.sin_family = AF_INET;
	to.sin_addr = address;
	to.sin_port = htons((unsigned short)request->port);
	p = FWD_peer_new(&to, &request->from, request->userinfo, request->qport, request->proto);

	Sys_DPrintf("peer %s:%d %s\n", inet_ntoa(request->from.sin_addr),
		(int)ntohs(request->from.sin_port), p ? "added or reused" : "was not added");
	if (!p)
		return;

	strlcpy(p->prx_host, request->host, sizeof(p->prx_host));

	{
		// The cvar is the server-wide default; a client may opt out per
		// connection with a "pathprobe" userinfo key. It stays a kill switch:
		// when disabled no client can turn probing back on.
		// Q3 does not support this probe method.
		qbool do_probe = sv_pathprobe_enable->integer && request->proto == pr_qw;
		char val[64];

		Info_ValueForKey(request->userinfo, "pathprobe", val, sizeof(val));
		if (val[0] && !atoi(val))
			do_probe = false;

		// no probe on this connect (opt-out, q3, chained): never keep a standby from an earlier one
		if (!do_probe)
			FWD_mp_close_alt(p);
		else if (p->ps == ps_challenge)
			FWD_PeerStartProbing(p);
		else if (p->ps == ps_pingprobe)
			Sys_DPrintf("Peer already probing, ignoring duplicate connect\n");
		else
			Sys_DPrintf("Peer reused, skipping probe (state %d)\n", p->ps);
	}

	if (request->proto == pr_qw)
	{
		// while probing, S2C_CONNECTION is sent when the probe finishes
		if (p->ps != ps_pingprobe)
			Netchan_OutOfBandPrint(request->socket, &request->from, "%c", S2C_CONNECTION);
	}
	else if (p->ps == ps_connected)
	{
		if (p->challenge == request->challenge)
			Netchan_OutOfBandPrint(request->socket, &request->from, "connectResponse");
		else
			Netchan_OutOfBandPrint(request->socket, &request->from, "print\n/reconnect ASAP!\n");
	}
}

static void SVC_ConnectError(connect_request_t *request, const char *message)
{
	if (request->proto == pr_qw)
		Netchan_OutOfBandPrint(request->socket, &request->from, "%c\n%s\n", A2C_PRINT, message);
	else
		Netchan_OutOfBandPrint(request->socket, &request->from, "print\n%s\n", message);
}

static qbool SVC_ProxyFull(connect_request_t *request)
{
	char message[MAX_INFO_STRING + 32];

	if (FWD_peers_count() < maxclients->integer)
		return false;

	snprintf(message, sizeof(message), "proxy@%s is full\n", hostname->string);
	SVC_ConnectError(request, message);
	return true;
}

static void SVC_RemovePendingConnect(pending_connect_t **link)
{
	pending_connect_t *pending = *link;
	peer_t *p = FWD_peer_by_addr(&pending->request.from);
	if (p)
		p->connect_pending = false;
	*link = pending->next;
	Sys_free(pending);
}

static qbool SVC_SameRoute(const connect_request_t *request, const char *host, unsigned short port, const char *userinfo)
{
	char current_chain[MAX_PRX_HOST], requested_chain[MAX_PRX_HOST];

	if ((unsigned short)request->port != port || stricmp(host, request->host))
		return false;

	Info_ValueForKey(userinfo, QWFWD_PRX_KEY, current_chain, sizeof(current_chain));
	Info_ValueForKey(request->userinfo, QWFWD_PRX_KEY, requested_chain, sizeof(requested_chain));
	return !stricmp(current_chain, requested_chain);
}

void SVC_CancelConnectForRoute(peer_t *p)
{
	pending_connect_t **link;

	for (link = &pending_connects; *link; link = &(*link)->next)
	{
		connect_request_t *request = &(*link)->request;

		if (!NET_CompareAddress(&request->from, &p->from))
			continue;

		if (request->proto == p->proto && request->qport == p->qport &&
			SVC_SameRoute(request, p->prx_host, ntohs(p->to.sin_port), p->userinfo))
			SVC_RemovePendingConnect(link);
		return;
	}
}

static void SVC_ConnectResolved(const struct in_addr *address, void *arg);

static connect_lookup_t *SVC_LookupConnectHost(connect_request_t *request)
{
	connect_lookup_t *lookup;
	int count = 0, count_for_ip = 0;

	for (lookup = connect_lookups; lookup; lookup = lookup->next)
	{
		if (!stricmp(lookup->host, request->host))
			return lookup;
		count++;
		if (NET_CompareBaseAddress(&lookup->owner, &request->from))
			count_for_ip++;
	}

	// Keep the lookup charged to its owner until the DNS callback runs.
	if (count_for_ip >= MAX_PENDING_CONNECTS_PER_IP)
	{
		SVC_ConnectError(request, "Too many DNS requests from your IP");
		return NULL;
	}

	if (count >= MAX_PRX_DNS_REQUESTS)
	{
		SVC_ConnectError(request, "Proxy DNS queue is full");
		return NULL;
	}

	lookup = Sys_malloc(sizeof(*lookup) + strlen(request->host) + 1);
	lookup->owner = request->from;
	strcpy(lookup->host, request->host);
	if (!NET_DNS_Resolve(lookup->host, SVC_ConnectResolved, lookup))
	{
		SVC_ConnectError(request, "Proxy DNS queue is full");
		Sys_free(lookup);
		return NULL;
	}

	lookup->next = connect_lookups;
	connect_lookups = lookup;
	return lookup;
}

static qbool SVC_CompleteConnect(pending_connect_t *pending, const struct in_addr *address)
{
	connect_request_t *request = &pending->request;
	unsigned int i = FindChallengeForAddr(&request->from);

	if (ps.wanttoexit || i >= MAX_CHALLENGES ||
		challenges[i].challenge != request->challenge || challenges[i].proto != request->proto ||
		SV_IsBanned(&request->from))
		return true;

	if (stricmp(pending->lookup->host, request->host))
	{
		// A newer connect asked for another host while this lookup was running.
		connect_lookup_t *lookup = SVC_LookupConnectHost(request);
		if (lookup)
		{
			pending->lookup = lookup;
			return false;
		}
	}
	else if (address)
	{
		if (FWD_peer_by_addr(&request->from) || !SVC_ProxyFull(request))
			SVC_FinishConnect(request, *address);
	}
	else
	{
		char message[sizeof(request->host) + 32];
		snprintf(message, sizeof(message), "Could not resolve %s", request->host);
		SVC_ConnectError(request, message);
	}

	return true;
}

static void SVC_ConnectResolved(const struct in_addr *address, void *arg)
{
	connect_lookup_t *lookup = arg, **lookup_link = &connect_lookups;
	pending_connect_t **link = &pending_connects, *pending;

	while (*lookup_link != lookup)
		lookup_link = &(*lookup_link)->next;
	*lookup_link = lookup->next;

	while ((pending = *link) != NULL)
	{
		if (pending->lookup != lookup || !SVC_CompleteConnect(pending, address))
		{
			link = &pending->next;
			continue;
		}

		SVC_RemovePendingConnect(link);
	}

	Sys_free(lookup);
}

static void SVC_StartConnect(connect_request_t *request)
{
	pending_connect_t **link = &pending_connects, *pending;
	struct in_addr address;
	peer_t *p;
	qbool same_pending_route;
	int count = 0, count_for_ip = 0;

	while ((pending = *link) != NULL)
	{
		if (NET_CompareAddress(&pending->request.from, &request->from))
			break;
		if (NET_CompareBaseAddress(&pending->request.from, &request->from))
			count_for_ip++;
		link = &pending->next;
		count++;
	}

	same_pending_route = pending && pending->request.proto == request->proto &&
		SVC_SameRoute(request, pending->request.host, pending->request.port, pending->request.userinfo);
	p = FWD_peer_by_addr(&request->from);
	if (!(same_pending_route && p) && SVC_ProxyFull(request))
	{
		if (pending && !same_pending_route)
			SVC_RemovePendingConnect(link);
		return;
	}

	if (NET_ParseIPv4(request->host, &address))
	{
		if (pending)
			SVC_RemovePendingConnect(link);
		SVC_FinishConnect(request, address);
		return;
	}

	if (!pending)
	{
		connect_lookup_t *lookup;

		if (count >= MAX_PENDING_CONNECTS)
		{
			SVC_ConnectError(request, "Proxy has too many pending connections");
			return;
		}
		if (count_for_ip >= MAX_PENDING_CONNECTS_PER_IP)
		{
			SVC_ConnectError(request, "Too many pending connections from your IP");
			return;
		}
		lookup = SVC_LookupConnectHost(request);
		if (!lookup)
			return;
		pending = Sys_malloc(sizeof(*pending));
		pending->lookup = lookup;
		pending->next = NULL;
		*link = pending;
	}
	else if (stricmp(pending->lookup->host, request->host))
	{
		connect_lookup_t *lookup;

		// Join a lookup already in flight. A new name waits for the current lookup to finish.
		for (lookup = connect_lookups; lookup; lookup = lookup->next)
		{
			if (!stricmp(lookup->host, request->host))
			{
				pending->lookup = lookup;
				break;
			}
		}
	}

	pending->request = *request;
	if (p)
	{
		time(&p->last);
		p->connect_pending = !(p->proto == pr_q3 && request->proto == pr_q3 &&
			p->qport == request->qport &&
			SVC_SameRoute(request, p->prx_host, ntohs(p->to.sin_port), p->userinfo));
	}
}

static void SVC_DirectConnect (void)
{
	unsigned int i = FindChallengeForAddr(&net_from);
	connect_request_t request = {0};
	char *userinfo = request.userinfo, *prx = request.host, *at;
	int qport, port, challenge;
	protocol_t proto;

	if ( i >= MAX_CHALLENGES )
	{
		// here protocol is unknown
		Netchan_OutOfBandPrint(net_from_socket, &net_from, "%c\nNo challenge for address.\n", A2C_PRINT);
		return;
	}

	proto = challenges[i].proto;

	// different for qw and q3
	if ( proto == pr_qw )
	{
		// check version/protocol
		if ( !CheckProtocol( atoi( Cmd_Argv( 1 ) ), proto ) )
			return; // wrong protocol number

		// get qport
		qport = atoi( Cmd_Argv( 2 ) );

		// see if the challenge is valid
		if ( !CheckChallenge( atoi( Cmd_Argv( 3 ) ) ) )
			return; // wrong challenge

		// and now validate userinfo
		if ( !CheckUserinfo( userinfo, sizeof(request.userinfo), Cmd_Argv( 4 ) ) )
			return; // wrong userinfo
	}
	else
	{
		// and now validate userinfo
		if ( !CheckUserinfo( userinfo, sizeof(request.userinfo), Cmd_Argv( 1 ) ) )
			return; // wrong userinfo

		// check version/protocol
		if ( !CheckProtocol( atoi( Info_ValueForKey(userinfo, "protocol", prx, sizeof(request.host)) ), proto ) )
			return; // wrong protocol number

		// get qport
		qport = atoi( Info_ValueForKey(userinfo, "qport", prx, sizeof(request.host)) );

		// see if the challenge is valid
		if ( !CheckChallenge( atoi( Info_ValueForKey(userinfo, "challenge", prx, sizeof(request.host)) ) ) )
			return; // wrong challenge
	}

	// check prx setinfo key
	Info_ValueForKey(userinfo, QWFWD_PRX_KEY, prx, sizeof(request.host));
	if (!prx[0])
	{
		if ( proto == pr_qw )
		{
			Netchan_OutOfBandPrint (net_from_socket, &net_from, "%c\n" QWFWD_PRX_KEY " userinfo key is not set\n", A2C_PRINT);
		}
		else
		{
			Netchan_OutOfBandPrint (net_from_socket, &net_from, "print\n" QWFWD_PRX_KEY " userinfo key is not set\n");
		}
		return; // no proxy set
	}

	// check chaining
	if ((at = strchr(prx, '@')) && at[1])
	{
		Info_SetValueForKeyEx(userinfo, QWFWD_PRX_KEY, at+1, sizeof(request.userinfo), false);
		at[0] = 0; // truncate proxy chains
	}
	else
	{
		Info_RemoveKey(userinfo, QWFWD_PRX_KEY);
	}

	// guess port
	if ((at = strchr(prx, ':')))
	{
		at[0] = 0; // truncate port from proxy name
		port = atoi(at + 1);
	}
	else
	{
		port = ( proto == pr_qw ) ? 27500 : 27960;
	}

	if (port < 1)
	{
		Netchan_OutOfBandPrint (net_from_socket, &net_from, "%c\nport number in " QWFWD_PRX_KEY " userinfo key is invalid\n", A2C_PRINT);
		return; // something wrong with port
	}

	// put some identifier in userinfo so server/proxy can detect that client use qwfwd.
	Info_SetValueForStarKey(userinfo, "*qwfwd", QWFWD_VERSION_SHORT, sizeof(request.userinfo));

	request.from = net_from;
	request.socket = net_from_socket;
	request.proto = proto;
	request.port = port;
	request.qport = qport;
	request.challenge = challenge;
	SVC_StartConnect(&request);
}

/*
================
SVC_Status

Responds with all the info that qplug or qspy can see
This message can be up to around 5k with worst case string lengths.
================
*/
#define STATUS_OLDSTYLE					0
#define	STATUS_SERVERINFO				1
#define	STATUS_PLAYERS					2
#define	STATUS_SPECTATORS				4
//#define STATUS_SPECTATORS_AS_PLAYERS	8 //for ASE - change only frags: show as "S"
//#define STATUS_SHOWTEAMS				16

static void SVC_Status (void)
{
	sizebuf_t buf;

	static byte buf_data[MSG_BUF_SIZE]; // static  - so it not allocated each time
	static char tmp[1024]; // static too

	int top, bottom, ping, opt, connect_t;
	char *name, *frags, *skin;
	peer_t *cl;

	SZ_InitEx(&buf, buf_data, sizeof(buf_data), true);

	MSG_WriteLong(&buf, -1);	// -1 sequence means out of band
	MSG_WriteChar(&buf, A2C_PRINT);

	opt = (Cmd_Argc() > 1) ? atoi(Cmd_Argv(1)) : 0;

	if (opt == STATUS_OLDSTYLE || (opt & STATUS_SERVERINFO))
	{
		snprintf(tmp, sizeof(tmp), "%s\n", ps.info);
		SZ_Print(&buf, tmp);
	}

	if (opt == STATUS_OLDSTYLE || (opt & (STATUS_PLAYERS | STATUS_SPECTATORS)))
	{
		for (cl = peers; cl; cl = cl->next)
		{
			top    = cl->top;
			bottom = cl->bottom;
			ping   = 666; //SV_CalcPing (cl);
			name   = cl->name;
			skin   = "";
			frags  = "0";
			connect_t = (int)(time(NULL) - cl->connect)/60; // not like it proper...

			snprintf(tmp, sizeof(tmp), "%i %s %i %i \"%s\" \"%s\" %i %i\n", cl->userid, frags, connect_t, ping, name, skin, top, bottom);

			SZ_Print(&buf, tmp);
		}
	}

	if (buf.overflowed)
		return; // overflowed

	// send the datagram
	NET_SendPacket(net_from_socket, buf.cursize, buf.data, &net_from);
}

/*
================
SVC_Ping

Just responds with an acknowledgement
================
*/
static void SVC_Ping (void)
{
	char data = A2A_ACK;

	NET_SendPacket(net_from_socket, 1, &data, &net_from);
}

/*
=================
SV_ConnectionlessPacket

A connectionless packet has four leading 0xff
characters to distinguish it from a game channel.
Clients that are in the game can still send
connectionless packets.
=================
*/

qbool SV_ConnectionlessPacket(void)
{
	qbool need_forward = false;
	char	*s;
	char	*c;

	MSG_BeginReading ();

	if (QRY_IsMasterReply())
	{
		SVC_QRY_ParseMasterReply();
	}
	else if (QRY_Mesh_IsMeshReply())
	{
		// binary mesh reply (from meshprobe) - MUST be intercepted here,
		// before MSG_ReadString()/Cmd_TokenizeString() below, which treat
		// the payload as a C string and would silently mangle/drop binary
		// data at the first embedded zero byte
		QRY_Mesh_HandleReply();
	}
	else
	{
		MSG_ReadLong ();		// skip the -1 marker

		s = MSG_ReadString ();//MSG_ReadStringLine ();

		// check for possibile huffmen compression for q3, zzz...
		if ( s[0] == 'c' && !strncmp(s, "connect ", sizeof("connect ")-1) )
		{
			unsigned int i = FindChallengeForAddr(&net_from);

			if ( i < MAX_CHALLENGES && challenges[i].proto == pr_q3 )
			{
				Huff_DecryptPacket(&net_message, 12);
				MSG_BeginReading();
				MSG_ReadLong();
				s = MSG_ReadString ();//MSG_ReadStringLine ();
			}
		}

//		Sys_Printf ("SV connectionless packet from %s:\n%s\n", inet_ntoa(net_from.sin_addr), s);

		Cmd_TokenizeString (s);

		c = Cmd_Argv(0);

		if (!strcmp(c, "ping") || ( c[0] == A2A_PING && (c[1] == 0 || c[1] == '\n') ) )
			SVC_Ping();
		else if (!strcmp(c, "pingstatus"))
			SVC_QRY_PingStatus();
		else if (!strcmp(c, "meshprobe"))
			SVC_QRY_MeshProbe();
		else if (!strcmp(c, "meshstatus"))
			SVC_QRY_MeshStatus();
		else if (!strcmp(c, "meshrelay"))
			SVC_MeshRelay();
		else if (!strcmp(c,"connect"))
			SVC_DirectConnect();
		else if (!strcmp(c,"getchallenge"))
			SVC_GetChallenge( !strcmp(s,"getchallenge\n") ? pr_qw : pr_q3 );
		else if (!strcmp(c,"status"))
			SVC_Status();
		else if (!strcmp(c,"rcon"))
			need_forward = true; // we do not have own rcon command, we forward it to the server...
	}

	return need_forward;
}

