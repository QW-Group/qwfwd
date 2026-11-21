#!/usr/bin/env python3
"""
Teste automatizado de integração para o protocolo mesh do qwfwd.

Sobe UMA instância real de qwfwd.exe (compilada com o patch) e fala com ela
via UDP puro, simulando: (1) um cliente pedindo meshprobe com nonce forjado
(deve ser ignorado, sem servers cadastrados = sem resposta útil ainda, mas
não deve crashar), (2) validação de que o processo continua vivo, (3)
validação de que pingstatus segue respondendo no formato antigo (regressão
de compatibilidade com ezquake).

Não depende de masters reais nem de internet - roda 100% local e
determinístico.
"""
import os
import socket
import struct
import subprocess
import sys
import time

QWFWD_EXE = os.environ.get("QWFWD_EXE", r"E:\Projetos Linux\qwfwd\build\qwfwd.exe")
PORT = 30099
HOST = "127.0.0.1"

results = []


def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    results.append((name, status, detail))
    print(f"[{status}] {name}" + (f" - {detail}" if detail else ""))
    return condition


def send_recv(sock, payload, timeout=2.0):
    sock.settimeout(timeout)
    sock.sendto(payload, (HOST, PORT))
    try:
        data, _ = sock.recvfrom(8192)
        return data
    except socket.timeout:
        return None


def main():
    print(f"Starting qwfwd on port {PORT}...")
    proc = subprocess.Popen(
        [QWFWD_EXE, str(PORT), "127.0.0.1"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(1.5)  # let it bind the socket

    check("process_alive_after_start", proc.poll() is None, f"exit code: {proc.poll()}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # --- Test 1: plain "ping" (A2A_PING) still works - sanity that the
        # process is actually listening and responding at all ---
        reply = send_recv(sock, b"\xff\xff\xff\xffk")
        check("baseline_ping_responds", reply is not None, f"reply={reply!r}" if reply else "no reply")

        # --- Test 2: pingstatus (existing protocol) still responds in the
        # OLD format: 0xff*4 + 'n' + N*8-byte entries (regression guard vs
        # ezquake's EX_browser_pathfind.c consumer) ---
        reply = send_recv(sock, b"\xff\xff\xff\xffpingstatus")
        old_format_ok = reply is not None and len(reply) >= 5 and reply[4:5] == b"n"
        check("pingstatus_unchanged_format", old_format_ok, f"reply={reply!r}" if reply else "no reply")
        if reply:
            # with zero servers known (no masters reachable in this isolated
            # test), payload should be empty - 5-byte header only
            check("pingstatus_empty_payload_when_no_servers", len(reply) == 5, f"len={len(reply)}")

        # --- Test 3: meshprobe with a forged/unsolicited nonce - the server
        # side (SVC_QRY_MeshProbe) should still reply (it always answers a
        # well-formed probe with its own 1-hop data), but since no servers
        # are known, the entry count must be 0. This exercises the new
        # magic+type+nonce framing end-to-end. ---
        fake_nonce = 424242
        probe = b"\xff\xff\xff\xffmeshprobe " + str(fake_nonce).encode()
        reply = send_recv(sock, probe)
        if check("meshprobe_replies", reply is not None, f"reply={reply!r}" if reply else "no reply"):
            magic_ok = reply[4:6] == b"QM"
            check("meshprobe_reply_magic", magic_ok, f"got={reply[4:6]!r}")
            msg_type = reply[6]
            check("meshprobe_reply_type_is_1", msg_type == 1, f"type={msg_type}")
            echoed_nonce = struct.unpack("<i", reply[7:11])[0]
            check("meshprobe_reply_echoes_nonce", echoed_nonce == fake_nonce, f"echoed={echoed_nonce}")
            check("meshprobe_reply_no_entries_when_no_servers", len(reply) == 11, f"len={len(reply)}")

        # --- Test 4: meshprobe with NO nonce argument - malformed query,
        # must be dropped silently (no reply), not crash the server ---
        reply = send_recv(sock, b"\xff\xff\xff\xffmeshprobe", timeout=1.0)
        check("meshprobe_no_nonce_dropped_silently", reply is None, f"unexpected reply={reply!r}")

        # --- Test 5: meshstatus - collector-facing query, with zero mesh
        # peers known it must reply with header only, no peer blocks ---
        reply = send_recv(sock, b"\xff\xff\xff\xffmeshstatus")
        if check("meshstatus_replies", reply is not None, f"reply={reply!r}" if reply else "no reply"):
            magic_ok = reply[4:6] == b"QM"
            check("meshstatus_reply_magic", magic_ok, f"got={reply[4:6]!r}")
            msg_type = reply[6]
            check("meshstatus_reply_type_is_2", msg_type == 2, f"type={msg_type}")
            check("meshstatus_empty_when_no_mesh_peers", len(reply) == 15, f"len={len(reply)}")
            next_index = struct.unpack("<i", reply[11:15])[0]
            check("meshstatus_next_index_is_minus_one_when_done", next_index == -1, f"next_index={next_index}")

        # --- Test 6: rate limiting - hammer meshprobe from the same source,
        # only the first reply within the window should arrive; a flood
        # must not be answered 1:1 (amplification guard) ---
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.settimeout(0.3)
        # The limiter keys by source IP, so let earlier protocol checks leave
        # the one-second window before testing a fresh burst.
        time.sleep(1.1)
        replies_received = 0
        for i in range(10):
            sock2.sendto(b"\xff\xff\xff\xffmeshprobe " + str(1000 + i).encode(), (HOST, PORT))
        time.sleep(0.5)
        try:
            while True:
                sock2.recvfrom(8192)
                replies_received += 1
        except socket.timeout:
            pass
        check("rate_limit_allows_first_reply", replies_received >= 1, f"got {replies_received}/10 replies")
        check("rate_limit_caps_flood_replies", replies_received < 10, f"got {replies_received}/10 replies")
        sock2.close()

        # --- Test 7: garbage/malformed binary that starts with the OOB
        # marker but isn't any known command - must not crash ---
        send_recv(sock, b"\xff\xff\xff\xff" + bytes(range(200)), timeout=0.5)
        time.sleep(0.3)
        check("survives_garbage_oob_packet", proc.poll() is None, f"exit code: {proc.poll()}")

        # --- Test 8: process still alive after everything above ---
        check("process_alive_at_end", proc.poll() is None, f"exit code: {proc.poll()}")

    finally:
        sock.close()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

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
