#!/usr/bin/env python3
"""
Real-server version of test_mesh_backup_route.py: real mvdsv (with
sv_proxy_migrate) + KTX, two real qwfwd, and a minimal QW client that does
the full signon (new / soundlist / modellist / prespawn / spawn / begin) and
then plays through proxy A. Mid game the route A -> server is blackholed;
the client must keep receiving the game through B without reconnecting.

Linux, root. Env: QWFWD_EXE, MVDSV_DIR (dir with ./mvdsv, id1/pak0.pak, ktx/qwprogs.so).
NO_MIGRATE=1 runs mvdsv with an empty sv_proxy_migrate: expect a switch, then
"multipath switch (rollback)" in A's log and the remaining checks to fail.
"""
import os
import re
import subprocess
import sys
import socket
import struct
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_mesh_backup_route as t  # netns setup, qwfwd launcher, addresses

MVDSV_DIR = os.environ.get("MVDSV_DIR", "/tmp/qwsrv")
PORT_S = 27500
OOB = b"\xff\xff\xff\xff"
QPORT = 4242
IP_CLIENT = "10.77.0.5"


def main():
    t.MASTER = ("10.77.0.4", 30200)
    srv = subprocess.Popen(["stdbuf", "-oL", "./mvdsv", "+developer", "1", "-port", str(PORT_S), "-game", "ktx",
                            "+sv_mapcheck", "0", "+sv_getrealip", "0", "+sv_proxy_migrate", ("" if os.environ.get("NO_MIGRATE") else "%s %s" % (t.IP_A, t.IP_B)), "+map", "dm4"],
                           cwd=MVDSV_DIR, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
    # fake master announces A, B and the real server
    t.PORT_S = PORT_S
    import threading
    threading.Thread(target=t.master, daemon=True).start()
    procs = [t.start_qwfwd(t.IP_A, t.PORT_A), t.start_qwfwd(t.IP_B, t.PORT_B)]
    print("waiting for mesh discovery...")
    # EARLY=1: connect before the mesh settled, the backup must be picked mid game
    early = bool(os.environ.get("EARLY"))
    time.sleep(3 if early else 25)
    kill_after = 30 if early else 6

    a = (t.IP_A, t.PORT_A)
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # own IP: the blackhole for the server must not cut A -> client
    subprocess.run("ip addr add %s/24 dev eqs" % IP_CLIENT, shell=True)
    c.bind((IP_CLIENT, 0))
    c.settimeout(2)
    c.sendto(OOB + b"getchallenge\n", a)
    chal = c.recvfrom(2048)[0][5:].split(b"\x00")[0].split()[0].decode()
    c.sendto(OOB + ('connect 28 %d %s "\\name\\migtest\\prx\\%s:%d"\n' % (QPORT, chal, t.IP_S, PORT_S)).encode(), a)
    while True:  # wait for 'j' (accept), skipping prints
        d = c.recvfrom(4096)[0]
        if d.startswith(OOB + b"j"):
            break
    c.settimeout(0.005)

    out_seq, in_seq, in_rel = 0, 0, 0
    pending = [b"new"]
    sent = set()
    sc = None  # servercount from svc_serverdata
    rx, killed_at, began = [], None, None
    t0 = time.time()
    while time.time() - t0 < 70:
        now = time.time()
        if began and not killed_at and now - began > kill_after:
            print("blackholing route A -> server")
            subprocess.run(["ip", "netns", "exec", "qa", "ip", "route", "add", "blackhole", "%s/32" % t.IP_S], check=True)
            killed_at = now
        if killed_at and now - killed_at > 10:
            break
        out_seq += 1
        payload = b""
        # qwfwd answers 'j' before its own connect to the server is done, so
        # keep asking for "new" until serverdata shows up (a real client does
        # the same through its reliable channel)
        if sc is None and not pending and out_seq % 40 == 0:
            pending.append(b"new")
        if pending:
            cmd = pending.pop(0)
            payload = b"\x04" + cmd + b"\x00"  # clc_stringcmd
            if cmd.startswith(b"begin"):
                began = now
        c.sendto(struct.pack("<IIH", out_seq, in_seq | (in_rel << 31), QPORT) + payload, a)
        end = now + 0.013
        while time.time() < end:
            try:
                d = c.recvfrom(8192)[0]
            except socket.timeout:
                continue
            if d.startswith(OOB) or len(d) < 8:
                continue
            seq = struct.unpack("<I", d[:4])[0]
            if (seq & 0x7fffffff) <= in_seq:
                continue
            in_seq = seq & 0x7fffffff
            if seq >> 31:
                in_rel ^= 1
            rx.append(time.time())
            body = d[8:]
            i = body.find(b"\x0b\x1c\x00\x00\x00")  # svc_serverdata, PROTOCOL_VERSION 28
            if sc is None and i >= 0:
                sc = struct.unpack("<i", body[i + 5:i + 9])[0]
                pending += [b"soundlist %d 0" % sc, b"modellist %d 0" % sc, b"prespawn %d 0 0" % sc]
            cmds = re.findall(rb"\x09cmd ([^\x00\n]*)\n", body)
            if sc is not None and re.search(rb"\x09skins\n", body):
                cmds.append(b"begin %d" % sc)
            for m in cmds:
                if m not in sent:
                    sent.add(m)
                    pending.append(m)

    srv.terminate()
    srv_out = srv.communicate(timeout=5)[0]
    outs = []
    for p in procs:
        p.terminate()
        outs.append(p.communicate(timeout=5)[0])

    ok = True
    if not killed_at:
        print("client never reached begin; rx=%d sc=%s sent=%s" % (len(rx), sc, sorted(sent)))
        killed_at = time.time()
        ok = False
    pts = [killed_at] + [x for x in rx if x > killed_at] + [time.time()]
    gap = max(b - a_ for a_, b in zip(pts, pts[1:]))
    for name, cond in (("client spawned (begin sent)", began is not None),
                       ("backup route via mesh chosen", "backup route via mesh" in outs[0]),
                       ("mvdsv migrated client to B", ("migrated %s" % t.IP_A) in srv_out and ("-> %s" % t.IP_B) in srv_out),
                       ("stream resumed after failure", len([x for x in rx if x > killed_at + 3]) > 100),
                       ("outage under 3 s", gap < 3.0)):
        print("[%s] %s" % ("PASS" if cond else "FAIL", name))
        ok &= cond
    print("max gap after failure: %.2fs" % gap)
    print("--- mvdsv (tail) ---\n" + "\n".join(srv_out.splitlines()[-15:]))
    if not ok:
        # the blackhole floods A's log with sendto errors, drop them
        a_log = "\n".join(l for l in outs[0].splitlines() if "sendto" not in l)
        print("--- A ---\n" + a_log[-2000:] + "\n--- B ---\n" + outs[1][-2000:])
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    if "--inner" in sys.argv:
        main()
    t.netns_setup()
    try:
        rc = subprocess.run(["ip", "netns", "exec", "qs", sys.executable, os.path.abspath(__file__), "--inner"]).returncode
    finally:
        for ns in t.NS:
            subprocess.run("ip netns del %s" % ns, shell=True)
    sys.exit(rc)
