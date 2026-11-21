#!/usr/bin/env python3
"""
Teste end-to-end: duas instâncias REAIS de qwfwd.exe, um "master" falso em
Python que apresenta cada proxy como servidor conhecido do outro, validando
que a descoberta+probe mesh acontece automaticamente, sem intervenção
manual, exatamente como aconteceria com masters reais na internet.

Config é feita via qwfwd.cfg (stdin não funciona: Sys_ReadSTDIN só lê se
isatty(STDIN), o que não é o caso de um processo filho com pipe).

Fluxo:
  1. Sobe master fake em UDP, respondendo "c\n" com os dois proxies.
  2. Cria um qwfwd.cfg por instância (cwd isolado) apontando pro master
     fake, limpando o filtro padrão que bloqueia 127.0.0.1, e encurtando
     os intervalos de mesh probe.
  3. Sobe qwfwd A (porta 30101) e qwfwd B (porta 30102).
  4. Espera o ciclo completo: master query -> descoberta -> ping direto ->
     mesh probe.
  5. Pergunta meshstatus para qwfwd A - se A descobriu B como mesh peer e
     armazenou o self-reported ping de B, o hop2 cache não estará vazio.
"""
import os
import socket
import struct
import subprocess
import sys
import threading
import time

QWFWD_EXE = os.environ.get("QWFWD_EXE", r"E:\Projetos Linux\qwfwd\build\qwfwd.exe")
HOST = "127.0.0.1"      # where the fake master and the test client bind/query
IP_A = "127.0.0.2"      # qwfwd instances bind to distinct loopback IPs to
IP_B = "127.0.0.3"      # dodge the default masters_filter_servers="127.0.0.1"
PORT_A = 30101
PORT_B = 30102
MASTER_PORT = 30100

WORKDIR_A = r"E:\Projetos Linux\qwfwd\_mesh-drafts\run-a"
WORKDIR_B = r"E:\Projetos Linux\qwfwd\_mesh-drafts\run-b"

results = []


def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    results.append((name, status, detail))
    print(f"[{status}] {name}" + (f" - {detail}" if detail else ""))
    return condition


def fake_master_thread(stop_event, log):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, MASTER_PORT))
    sock.settimeout(0.3)

    entry_a = bytes([127, 0, 0, 2]) + struct.pack(">H", PORT_A)
    entry_b = bytes([127, 0, 0, 3]) + struct.pack(">H", PORT_B)
    reply = b"\xff\xff\xff\xff\x64\x0a" + entry_a + entry_b

    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(1024)
            # QRY_QueryMasters sends QW_MASTER_QUERY via sizeof() on a C
            # string literal, which includes the trailing NUL - real wire
            # bytes are b"c\n\x00", not b"c\n". Accept both to be safe.
            if data.rstrip(b"\x00") == b"c\n":
                sock.sendto(reply, addr)
                log.append(f"master: replied to {addr}")
        except socket.timeout:
            continue
    sock.close()


def start_qwfwd(port, bind_ip, workdir, name):
    os.makedirs(workdir, exist_ok=True)
    # cvars registered by QRY_Init() do not exist yet when qwfwd.cfg is
    # exec'd at boot (Cbuf_Execute for qwfwd.cfg runs BEFORE QRY_Init in
    # main.c), so config must go through Cmd_StuffCmds instead (argv[1]=port,
    # argv[2]=ip, then '+cmds' - all after ip run AFTER QRY_Init).
    # masters_filter_servers defaults to "127.0.0.1" and Cmd_StuffCmds'
    # tokenizer has no quoting, so it cannot be cleared to "" this way -
    # instead each instance binds to a distinct 127.0.0.x to dodge the filter
    # entirely rather than fighting the parser.
    args = [
        QWFWD_EXE, str(port), bind_ip,
        "+masters", f"127.0.0.1:{MASTER_PORT}",
        "+mesh_probe_interval", "1",
        "+mesh_query_interval", "1",
    ]
    proc = subprocess.Popen(
        args,
        cwd=workdir,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    print(f"Started {name} on {bind_ip}:{port} (pid {proc.pid}, cwd {workdir})")
    return proc


def query_meshstatus(ip, port, timeout=2.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(b"\xff\xff\xff\xffmeshstatus", (ip, port))
    try:
        data, _ = sock.recvfrom(8192)
        return data
    except socket.timeout:
        return None
    finally:
        sock.close()


def main():
    stop_event = threading.Event()
    master_log = []
    master_thread = threading.Thread(target=fake_master_thread, args=(stop_event, master_log), daemon=True)
    master_thread.start()
    time.sleep(0.3)

    proc_a = start_qwfwd(PORT_A, IP_A, WORKDIR_A, "qwfwd-A")
    proc_b = start_qwfwd(PORT_B, IP_B, WORKDIR_B, "qwfwd-B")

    time.sleep(1)
    check("both_processes_alive_after_start", proc_a.poll() is None and proc_b.poll() is None)

    print("Waiting for discovery + mesh probe cycle...")
    time.sleep(10)

    print(f"Master query log: {master_log}")

    reply_a = query_meshstatus(IP_A, PORT_A)
    reply_b = query_meshstatus(IP_B, PORT_B)

    check("meshstatus_a_responds", reply_a is not None, f"reply={reply_a!r}" if reply_a else "no reply")
    check("meshstatus_b_responds", reply_b is not None, f"reply={reply_b!r}" if reply_b else "no reply")

    def has_mesh_data(reply):
        return reply is not None and len(reply) > 11

    a_discovered_mesh = has_mesh_data(reply_a)
    b_discovered_mesh = has_mesh_data(reply_b)

    check(
        "a_discovered_b_as_mesh_peer",
        a_discovered_mesh,
        f"meshstatus payload len={len(reply_a) if reply_a else 0} (want >11)",
    )
    check(
        "b_discovered_a_as_mesh_peer",
        b_discovered_mesh,
        f"meshstatus payload len={len(reply_b) if reply_b else 0} (want >11)",
    )

    if a_discovered_mesh:
        # QW wire integers (MSG_WriteShort/Long) are little-endian; only the
        # raw 4-byte IP itself is left as network-order bytes (not a number
        # to byte-swap, just read left-to-right as octets). Header is now
        # 15 bytes (11 base + 4-byte next_index pagination cursor).
        peer_ip_raw = reply_a[15:19]
        peer_port = struct.unpack("<H", reply_a[19:21])[0]
        peer_age = struct.unpack("<h", reply_a[21:23])[0]
        peer_count = struct.unpack("<h", reply_a[23:25])[0]
        print(f"  A sees mesh peer {'.'.join(str(b) for b in peer_ip_raw)}:{peer_port} age={peer_age}s hop2_count={peer_count}")
        check("a_sees_b_port", peer_port == PORT_B, f"got port {peer_port}, want {PORT_B}")

    stop_event.set()

    outs = {}
    for proc, tag in ((proc_a, "A"), (proc_b, "B")):
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
        outs[tag] = out

    if not (a_discovered_mesh and b_discovered_mesh):
        print("\n--- qwfwd-A stdout (tail) ---")
        print(outs["A"][-2000:] if outs["A"] else "(empty)")
        print("\n--- qwfwd-B stdout (tail) ---")
        print(outs["B"][-2000:] if outs["B"] else "(empty)")

    print("\n--- SUMMARY ---")
    passed = sum(1 for _, s, _ in results if s == "PASS")
    total = len(results)
    print(f"{passed}/{total} passed")
    for name, status, detail in results:
        if status == "FAIL":
            print(f"  FAILED: {name} - {detail}")

    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
