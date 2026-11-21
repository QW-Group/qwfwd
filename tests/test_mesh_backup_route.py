#!/usr/bin/env python3
"""
End-to-end check of the mesh backup route (multipath via another qwfwd).

Two real qwfwd instances (A, B), a fake master and a fake QW server that
applies the same migration rule as mvdsv's sv_proxy_migrate (qport match,
both IPs trusted, newer sequence). A fake client plays through A. Mid game
the server stops talking to A's IP: the client must keep receiving the
stream, now carried by B, without any reconnect.

Linux, root (network namespaces, so each proxy has its own source IP):
  QWFWD_EXE=/path/to/qwfwd python3 tests/test_mesh_backup_route.py
"""
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

QWFWD_EXE = os.environ.get("QWFWD_EXE", "/tmp/qfb/qwfwd")
IP_A, PORT_A = "10.77.0.2", 30201
IP_B, PORT_B = "10.77.0.3", 30202
IP_S, PORT_S = "10.77.0.4", 30203   # fake server, master and client live here
MASTER = (IP_S, 30200)
NS = {"qa": IP_A, "qb": IP_B, "qs": IP_S}


def sh(cmd):
    subprocess.run(cmd, shell=True, check=True)


def netns_setup():
    for ns in NS:
        subprocess.run("ip netns del %s" % ns, shell=True, stderr=subprocess.DEVNULL)
    for ns in NS:
        sh("ip netns add %s && ip -n %s link set lo up" % (ns, ns))
    sh("ip -n qs link add br0 type bridge && ip -n qs link set br0 up")
    for ns, ip in NS.items():
        sh("ip link add v%s type veth peer name e%s" % (ns, ns))
        sh("ip link set v%s netns qs && ip -n qs link set v%s master br0 && ip -n qs link set v%s up" % (ns, ns, ns))
        sh("ip link set e%s netns %s && ip -n %s addr add %s/24 dev e%s && ip -n %s link set e%s up" % (ns, ns, ns, ip, ns, ns, ns))
TRUSTED = {IP_A, IP_B}
OOB = b"\xff\xff\xff\xff"

stop = threading.Event()
state = {"dead_ip": None, "migrated": [], "clients": {}}


def master():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(MASTER)
    s.settimeout(0.3)
    entries = b"".join(socket.inet_aton(ip) + struct.pack(">H", p)
                       for ip, p in ((IP_A, PORT_A), (IP_B, PORT_B), (IP_S, PORT_S)))
    while not stop.is_set():
        try:
            data, addr = s.recvfrom(1024)
        except socket.timeout:
            continue
        if data.rstrip(b"\x00") == b"c\n":
            s.sendto(OOB + b"\x64\x0a" + entries, addr)


def server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((IP_S, PORT_S))
    s.settimeout(0.01)
    out_seq = 0
    clients = state["clients"]  # qport -> [addr, last_seq]
    last_tick = time.time()
    while not stop.is_set():
        try:
            data, addr = s.recvfrom(2048)
        except socket.timeout:
            data = None
        if data and addr[0] != state["dead_ip"]:
            if data.startswith(OOB):
                cmd = data[4:]
                if cmd.startswith(b"ping") or cmd[:1] == b"k":
                    s.sendto(b"l", addr)
                elif cmd.startswith(b"getchallenge"):
                    s.sendto(OOB + b"c12345", addr)
                elif cmd.startswith(b"connect"):
                    s.sendto(OOB + b"j", addr)
            elif len(data) >= 10:
                seq, _, qport = struct.unpack("<IIH", data[:10])
                c = clients.get(qport)
                if c is None:
                    clients[qport] = [addr, seq]
                elif c[0] == addr or (c[0][0] == addr[0]):
                    c[0], c[1] = addr, max(c[1], seq)
                elif addr[0] in TRUSTED and c[0][0] in TRUSTED and c[1] < seq <= c[1] + 1000:
                    state["migrated"].append((c[0], addr))
                    c[0], c[1] = addr, seq
        # stream ~77 pps to every client, like sv fps
        if time.time() - last_tick > 0.013:
            last_tick = time.time()
            for addr, _ in clients.values():
                if addr[0] != state["dead_ip"]:
                    out_seq += 1
                    s.sendto(struct.pack("<II", out_seq, 0) + b"\x00" * 20, addr)


def start_qwfwd(ip, port):
    wd = tempfile.mkdtemp()
    ns = [n for n, i in NS.items() if i == ip][0]
    return subprocess.Popen(["ip", "netns", "exec", ns, QWFWD_EXE, str(port), ip, "+masters", "%s:%d" % MASTER,
                             "+mesh_probe_interval", "1", "+mesh_query_interval", "1"],
                            cwd=wd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)


def main():
    for f in (master, server):
        threading.Thread(target=f, daemon=True).start()
    procs = [start_qwfwd(IP_A, PORT_A), start_qwfwd(IP_B, PORT_B)]
    print("waiting for mesh discovery...")
    time.sleep(25)

    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.bind((IP_S, 0))
    c.settimeout(1)
    c.sendto(OOB + b"meshstatus", (IP_A, PORT_A))
    try:
        ms = c.recvfrom(8192)[0]
        print("A meshstatus: %d bytes, hop2 entries %d" % (len(ms), struct.unpack("<h", ms[23:25])[0] if len(ms) > 25 else -1))
    except socket.timeout:
        print("A meshstatus: no reply")
    c.settimeout(0.01)
    a = (IP_A, PORT_A)
    c.sendto(OOB + b"getchallenge\n", a)
    data, _ = c.recvfrom(2048)
    chal = data[5:].split(b"\x00")[0].strip().decode()
    c.sendto(OOB + ('connect 28 777 %s "\\name\\t\\prx\\%s:%d"\n' % (chal, IP_S, PORT_S)).encode(), a)

    seq, rx = 0, []
    t0 = time.time()
    while time.time() - t0 < 16:
        if time.time() - t0 > 6 and state["dead_ip"] is None:
            print("killing route A -> server")
            state["dead_ip"] = IP_A
            t_kill = time.time()
        seq += 1
        c.sendto(struct.pack("<IIH", seq, 0, 777) + b"\x00" * 8, a)
        end = time.time() + 0.013
        while time.time() < end:
            try:
                d, _ = c.recvfrom(2048)
                if not d.startswith(OOB):
                    rx.append(time.time())
            except socket.timeout:
                pass

    stop.set()
    outs = []
    for p in procs:
        p.terminate()
        outs.append(p.communicate(timeout=5)[0])

    before = [t for t in rx if t < t_kill]
    after = [t for t in rx if t > t_kill + 3]
    pts = [t_kill] + [t for t in rx if t > t_kill] + [time.time()]
    gap = max(b - a for a, b in zip(pts, pts[1:]))
    ok = True
    for name, cond in (("stream before failure", len(before) > 100),
                       ("backup route via mesh chosen", "backup route via mesh" in outs[0]),
                       ("server migrated client to B", any(n[0] == IP_B for _, n in state["migrated"])),
                       ("stream resumed after failure", len(after) > 100),
                       ("outage under 3 s", gap < 3.0)):
        print("[%s] %s" % ("PASS" if cond else "FAIL", name))
        ok &= cond
    print("max gap after failure: %.2fs" % gap)
    if not ok:
        print("--- A ---\n" + outs[0][-3000:] + "\n--- B ---\n" + outs[1][-3000:])
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    if "--inner" in sys.argv:
        main()
    netns_setup()
    try:
        rc = subprocess.run(["ip", "netns", "exec", "qs", sys.executable, os.path.abspath(__file__), "--inner"]).returncode
    finally:
        for ns in NS:
            subprocess.run("ip netns del %s" % ns, shell=True)
    sys.exit(rc)
