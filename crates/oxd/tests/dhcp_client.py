"""A minimal DHCP client for tests: DISCOVER, OFFER, REQUEST, ACK.

It talks in raw Ethernet frames on one interface, so it works next to the
server in the same network namespace and is not affected by the firewall
under test on the client side. Prints `address server lease-seconds`.

Usage: dhcp_client.py <interface> <mac> [hostname]
"""

import socket
import struct
import sys
import time

MAGIC = b"\x63\x82\x53\x63"


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def frame(mac, xid, options):
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0, 0x8000,
                        b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4, mac, b"", b"")
    payload = bootp + MAGIC + options + b"\xff"
    udp = struct.pack("!HHHH", 68, 67, 8 + len(payload), 0) + payload
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                       bytes(4), b"\xff" * 4)
    ip = head[:10] + struct.pack("!H", checksum(head)) + head[12:]
    return b"\xff" * 6 + mac + b"\x08\x00" + ip + udp


def option(code, value):
    return bytes([code, len(value)]) + value


def reply(sock, xid, want, deadline):
    """Waits for a server message of DHCP type `want` for this transaction."""
    while time.time() < deadline:
        sock.settimeout(max(0.05, deadline - time.time()))
        try:
            data = sock.recv(2048)
        except socket.timeout:
            break
        if len(data) < 14 + 20 + 8 + 240 or data[12:14] != b"\x08\x00" or data[23] != 17:
            continue
        ihl = (data[14] & 0x0F) * 4
        udp = 14 + ihl
        if struct.unpack("!HH", data[udp:udp + 4]) != (67, 68):
            continue
        bootp = data[udp + 8:]
        if bootp[0] != 2 or struct.unpack("!I", bootp[4:8])[0] != xid or bootp[236:240] != MAGIC:
            continue
        options, i = {}, 240
        while i < len(bootp) and bootp[i] != 255:
            if bootp[i] == 0:
                i += 1
                continue
            options[bootp[i]] = bootp[i + 2:i + 2 + bootp[i + 1]]
            i += 2 + bootp[i + 1]
        if options.get(53) == bytes([want]):
            return bootp[16:20], options
    sys.exit("no DHCP reply of type %d" % want)


def main():
    iface, mac = sys.argv[1], bytes.fromhex(sys.argv[2].replace(":", ""))
    name = sys.argv[3].encode() if len(sys.argv) > 3 else b""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.bind((iface, 0))
    xid = int.from_bytes(mac[2:], "big") ^ 0x5A5A5A5A
    deadline = time.time() + 8

    sock.send(frame(mac, xid, option(53, b"\x01")))
    offered, options = reply(sock, xid, 2, deadline)
    request = option(53, b"\x03") + option(50, offered) + option(54, options[54])
    if name:
        request += option(12, name)
    sock.send(frame(mac, xid, request))
    address, options = reply(sock, xid, 5, deadline)
    print(socket.inet_ntoa(address), socket.inet_ntoa(options[54]),
          struct.unpack("!I", options[51])[0])


main()
