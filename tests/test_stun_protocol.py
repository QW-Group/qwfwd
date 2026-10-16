#!/usr/bin/env python3
"""
Teste automatizado de integração para o STUN responder (opt-in) do qwfwd.

Sobe UMA instância real de qwfwd.exe com stun_enable=1 e fala com ela via
UDP puro construindo pacotes STUN (RFC 5389) crus, validando: (1) Binding
Request bem formado recebe Binding Response correto byte a byte, incluindo
o XOR-MAPPED-ADDRESS calculado certo; (2) pacotes malformados/truncados são
descartados silenciosamente (sem resposta, sem crash); (3) rate limiting
por IP funciona (flood não é respondido 1:1); (4) com stun_enable=0
(default), nenhum Binding Request é respondido, e o dispatch Quake normal
(pingstatus) continua intocado.

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
HOST = "127.0.0.1"

STUN_MAGIC_COOKIE = 0x2112A442
STUN_TYPE_BINDING_REQUEST = 0x0001
STUN_TYPE_BINDING_SUCCESS = 0x0101
STUN_ATTR_XOR_MAPPED_ADDR = 0x0020

results = []


def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    results.append((name, status, detail))
    print(f"[{status}] {name}" + (f" - {detail}" if detail else ""))
    return condition


def build_binding_request(transaction_id: bytes) -> bytes:
    assert len(transaction_id) == 12
    header = struct.pack(">HHI", STUN_TYPE_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE)
    return header + transaction_id


def send_recv(sock, payload, addr_port, timeout=1.5):
    sock.settimeout(timeout)
    sock.sendto(payload, (HOST, addr_port))
    try:
        data, _ = sock.recvfrom(8192)
        return data
    except socket.timeout:
        return None


def start_qwfwd(port, extra_args):
    args = [QWFWD_EXE, str(port), "127.0.0.1"] + extra_args
    proc = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(1.5)  # let it bind the socket and run init (incl. STUN_Init)
    return proc


def test_stun_enabled():
    port = 30098
    proc = start_qwfwd(port, ["+stun_enable", "1", "+stun_rate_per_ip", "3"])
    check("enabled_process_alive_after_start", proc.poll() is None, f"exit code: {proc.poll()}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    my_port = sock.getsockname()[1]

    try:
        # --- Test 1: well-formed Binding Request gets a correct Binding
        # Response, byte for byte, including XOR-MAPPED-ADDRESS ---
        txid = bytes(range(12))
        reply = send_recv(sock, build_binding_request(txid), port)
        if check("binding_request_gets_reply", reply is not None, f"reply={reply!r}" if reply else "no reply"):
            check("reply_length_is_32", len(reply) == 32, f"len={len(reply)}")
            msg_type, msg_len, cookie = struct.unpack(">HHI", reply[0:8])
            check("reply_type_is_binding_success", msg_type == STUN_TYPE_BINDING_SUCCESS, f"type={msg_type:#06x}")
            check("reply_attr_len_is_12", msg_len == 12, f"len={msg_len}")
            check("reply_echoes_magic_cookie", cookie == STUN_MAGIC_COOKIE, f"cookie={cookie:#010x}")
            check("reply_echoes_transaction_id", reply[8:20] == txid, f"got={reply[8:20]!r}")

            attr_type, attr_len = struct.unpack(">HH", reply[20:24])
            check("reply_attr_is_xor_mapped_address", attr_type == STUN_ATTR_XOR_MAPPED_ADDR, f"attr_type={attr_type:#06x}")
            check("reply_attr_value_len_is_8", attr_len == 8, f"len={attr_len}")

            family = reply[25]
            check("reply_family_is_ipv4", family == 0x01, f"family={family}")

            xor_port = struct.unpack(">H", reply[26:28])[0]
            got_port = xor_port ^ (STUN_MAGIC_COOKIE >> 16)
            check("reply_xor_port_decodes_to_our_source_port", got_port == my_port, f"decoded={got_port} expected={my_port}")

            xor_addr = struct.unpack(">I", reply[28:32])[0]
            got_ip = xor_addr ^ STUN_MAGIC_COOKIE
            expected_ip = struct.unpack(">I", socket.inet_aton("127.0.0.1"))[0]
            check("reply_xor_address_decodes_to_127_0_0_1", got_ip == expected_ip, f"decoded={socket.inet_ntoa(struct.pack('>I', got_ip))}")

        # --- Test 2: wrong magic cookie - must be silently dropped ---
        bad = struct.pack(">HHI", STUN_TYPE_BINDING_REQUEST, 0, 0xDEADBEEF) + bytes(range(12))
        reply = send_recv(sock, bad, port, timeout=0.5)
        check("wrong_magic_cookie_dropped_silently", reply is None, f"unexpected reply={reply!r}")

        # --- Test 3: declared length doesn't match actual packet size -
        # must be dropped silently, not crash ---
        bad = struct.pack(">HHI", STUN_TYPE_BINDING_REQUEST, 100, STUN_MAGIC_COOKIE) + bytes(range(12))
        reply = send_recv(sock, bad, port, timeout=0.5)
        check("length_mismatch_dropped_silently", reply is None, f"unexpected reply={reply!r}")
        check("survives_length_mismatch", proc.poll() is None, f"exit code: {proc.poll()}")

        # --- Test 4: truncated packet (below STUN header size) - dropped,
        # falls through to Quake's own connectionless dispatch harmlessly
        # (this is NOT the 0xFFFFFFFF OOB marker, so Quake also won't
        # recognize it as anything - just must not crash) ---
        reply = send_recv(sock, b"\x00\x01\x00\x00", port, timeout=0.5)
        check("truncated_packet_dropped_silently", reply is None, f"unexpected reply={reply!r}")
        check("survives_truncated_packet", proc.poll() is None, f"exit code: {proc.poll()}")

        # --- Test 5: existing Quake protocol (pingstatus) still works
        # unaffected by the new STUN check in peer.c's dispatch ---
        reply = send_recv(sock, b"\xff\xff\xff\xffpingstatus", port)
        old_format_ok = reply is not None and len(reply) >= 5 and reply[4:5] == b"n"
        check("pingstatus_unaffected_by_stun_dispatch", old_format_ok, f"reply={reply!r}" if reply else "no reply")

        # --- Test 6: rate limiting - stun_rate_per_ip=3, hammer with 10
        # requests from the same source, only the first few should reply ---
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.settimeout(0.3)
        for i in range(10):
            txid_i = bytes([i]) + bytes(range(11))
            sock2.sendto(build_binding_request(txid_i), (HOST, port))
        time.sleep(0.5)
        replies_received = 0
        try:
            while True:
                sock2.recvfrom(8192)
                replies_received += 1
        except socket.timeout:
            pass
        check("rate_limit_caps_flood_replies", replies_received < 10, f"got {replies_received}/10 replies")
        check("rate_limit_allows_some_replies", replies_received > 0, f"got {replies_received}/10 replies")
        sock2.close()

        check("enabled_process_alive_at_end", proc.poll() is None, f"exit code: {proc.poll()}")
    finally:
        sock.close()
        proc.terminate()
        proc.wait(timeout=5)


def test_stun_disabled_by_default():
    port = 30097
    proc = start_qwfwd(port, [])  # no +stun_enable at all - must default off
    check("disabled_process_alive_after_start", proc.poll() is None, f"exit code: {proc.poll()}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # --- Test 7: with the default (off) config, a well-formed Binding
        # Request must get NO reply at all - opt-in means opt-in ---
        txid = bytes(range(12))
        reply = send_recv(sock, build_binding_request(txid), port, timeout=0.7)
        check("stun_disabled_by_default_no_reply", reply is None, f"unexpected reply={reply!r}")

        # --- Test 8: existing protocol still fine with the feature off ---
        reply = send_recv(sock, b"\xff\xff\xff\xffpingstatus", port)
        old_format_ok = reply is not None and len(reply) >= 5 and reply[4:5] == b"n"
        check("pingstatus_works_with_stun_disabled", old_format_ok, f"reply={reply!r}" if reply else "no reply")

        check("disabled_process_alive_at_end", proc.poll() is None, f"exit code: {proc.poll()}")
    finally:
        sock.close()
        proc.terminate()
        proc.wait(timeout=5)


def main():
    print("=== stun_enable=1 ===")
    test_stun_enabled()
    print("\n=== stun_enable default (off) ===")
    test_stun_disabled_by_default()

    failed = [r for r in results if r[1] == "FAIL"]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    if failed:
        print("FAILURES:")
        for name, status, detail in failed:
            print(f"  - {name}: {detail}")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
