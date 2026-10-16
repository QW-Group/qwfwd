#!/usr/bin/env python3
"""Black-box UDP tests; no public server or third-party Python package needed."""
import collections
import heapq
import os
import re
import select
import socket
import subprocess
import sys
import tempfile
import time

OOB = b"\xff" * 4
REPORT = re.compile(rb"Source port (\d+): min proxy-server RTT ([\d.]+) ms \((\d+)/3 replies, (\d+) ports\)")


def udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    return sock


def scenario(binary, name, count, delays, expected_index=None, expected_samples=3,
             deadline=1000, reconnect=False, noise=False):
    with udp() as server, udp() as stranger, udp() as client, udp() as reservation:
        proxy = reservation.getsockname()
        reservation.close()
        with tempfile.TemporaryDirectory(prefix="qwfwd-test-") as directory:
            with tempfile.TemporaryFile() as log:
                proc = subprocess.Popen(
                    [binary, str(proxy[1]), proxy[0], "+developer", "1",
                     "+masters_query", "0", "+masters_heartbeat", "0",
                     "+sv_pathprobe_count", str(count),
                     "+sv_pathprobe_delay", str(deadline)],
                    cwd=directory, stdout=log, stderr=log)
                try:
                    # Readiness and challenge acquisition are harmless UDP requests.
                    client.settimeout(0.05)
                    stop = time.monotonic() + 5
                    while True:
                        assert proc.poll() is None, "proxy exited during startup"
                        client.sendto(OOB + b"getchallenge\n", proxy)
                        try:
                            data = client.recv(8192)
                            match = re.match(rb"\xff{4}c(-?\d+)", data)
                            if match:
                                challenge = match.group(1)
                                break
                        except socket.timeout:
                            pass
                        assert time.monotonic() < stop, "no challenge"
                    client.setblocking(False)
                    info = (f"\\name\\pathprobe-test\\prx\\127.0.0.1:{server.getsockname()[1]}").encode()
                    connect = OOB + b"connect 28 12345 " + challenge + b' "' + info + b'"\n'
                    old_winner = None
                    for cycle in range(2 if reconnect else 1):
                        ports = []
                        requests = collections.Counter()
                        scheduled = []
                        report = None
                        connected_port = None
                        acknowledged = False
                        started = time.monotonic()
                        client.sendto(connect, proxy)
                        if old_winner is not None:
                            # Late game traffic reaches the reused socket AFTER its
                            # initial drain, before any legitimate probe reply.
                            for offset in (0.003, 0.006, 0.009):
                                heapq.heappush(scheduled, (started + offset, b"game-packet", old_winner))
                        stop = started + 5
                        while time.monotonic() < stop:
                            now = time.monotonic()
                            while scheduled and scheduled[0][0] <= now:
                                _, payload, address = heapq.heappop(scheduled)
                                server.sendto(payload, address)
                            wait = max(0, min(0.05, scheduled[0][0] - now)) if scheduled else 0.05
                            ready, _, _ = select.select([server, client], [], [], wait)
                            for sock in ready:
                                data, address = sock.recvfrom(8192)
                                if sock is client:
                                    if REPORT.search(data):
                                        report = REPORT.search(data)
                                    if data.startswith(OOB + b"j"):
                                        acknowledged = True
                                    continue
                                if data.startswith(OOB + b"ping"):
                                    if address not in ports:
                                        ports.append(address)
                                    index = ports.index(address)
                                    sample = requests[address]
                                    requests[address] += 1
                                    if noise:
                                        # Includes the right byte with wrong length,
                                        # connectionless header, and wrong sender.
                                        for payload in (b"x", b"l-extra", OOB + b"l", b"game-packet"):
                                            server.sendto(payload, address)
                                        stranger.sendto(b"l", address)
                                    delay = delays(index, sample)
                                    if delay is not None:
                                        heapq.heappush(scheduled, (time.monotonic() + delay, b"l", address))
                                elif data.startswith(OOB + b"getchallenge"):
                                    server.sendto(OOB + b"c123\x00", address)
                                elif data.startswith(OOB + b"connect"):
                                    connected_port = address
                                    server.sendto(OOB + b"j", address)
                            if connected_port is not None and acknowledged:
                                break
                        assert connected_port is not None and acknowledged, "connection did not complete"
                        assert len(ports) == count, (len(ports), count)
                        if expected_index is None:
                            assert report is None, "invalid packets produced a fabricated RTT"
                            assert all(n == 1 for n in requests.values()), "invalid replies advanced sampling"
                            assert connected_port == ports[0], "no-reply fallback changed socket"
                        else:
                            assert connected_port == ports[expected_index], (connected_port, ports)
                            assert report is not None, "missing RTT report"
                            assert int(report[1]) == connected_port[1], "reported source port differs from connection"
                            assert int(report[3]) == expected_samples, report.group()
                            assert int(report[4]) == count, report.group()
                            expected_min = min(delays(expected_index, sample) for sample in range(expected_samples)) * 1000
                            measured = float(report[2])
                            assert expected_min - 1 <= measured < expected_min + 20, (measured, expected_min)
                        if expected_samples == 3 and expected_index is not None:
                            assert all(n == 3 for n in requests.values()), requests
                        old_winner = connected_port
                    print(f"PASS {name}")
                finally:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                    log.seek(0)
                    output = log.read().decode(errors="replace")
                    if sys.exc_info()[0] is not None:
                        print(output, file=sys.stderr)
                    assert "ERROR: AddressSanitizer" not in output, output
                    assert "runtime error:" not in output, output


def main():
    binary = os.path.abspath(sys.argv[1])
    scenario(binary, "third sample changes winner", 2,
             lambda i, n: 0.030 if i == 0 else (0.006 if n == 2 else 0.050), 1)
    scenario(binary, "reject invalid replies and preserve socket on reconnect", 2,
             lambda i, n: 0.030 if i == 0 else 0.060, 0, noise=True, reconnect=True)
    scenario(binary, "only invalid replies: no RTT and original socket", 2,
             lambda i, n: None, deadline=150, noise=True)
    scenario(binary, "deadline reports partial sampling", 1,
             lambda i, n: 0.020 if n == 0 else None, 0, expected_samples=1, deadline=150)
    scenario(binary, "64 candidates and a winner beyond the old limit", 64,
             lambda i, n: 0.010 if i == 63 else 0.080, 63)


if __name__ == "__main__":
    main()
