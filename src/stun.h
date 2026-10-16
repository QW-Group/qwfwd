/*
	stun.h - minimal RFC 5389 STUN Binding Request/Response responder

	Lets a browser measure real RTT to this proxy via RTCPeerConnection
	ICE-gathering, without needing HTTPS/a certificate per proxy (the
	browser cannot open raw UDP sockets, but a STUN "server" is exactly
	the kind of UDP peer WebRTC already knows how to time). Opt-in,
	default off. See stun.c for the full security rationale.
*/
#ifndef __STUN_H__
#define __STUN_H__

void STUN_Init(void);

// Called from peer.c's read loop, before Quake's own connectionless
// dispatch, since a STUN packet does not start with the 0xFFFFFFFF OOB
// marker and would otherwise be silently rejected/misrouted. Returns
// true if the packet was recognized and handled as STUN (caller should
// not process it further), false otherwise (not STUN, or stun_enable is
// off - fall through to normal Quake packet handling).
qbool STUN_HandlePacket(const byte *data, int len, struct sockaddr_in *from);

#endif // __STUN_H__
