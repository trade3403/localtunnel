"""Real isolated QUIC application admission limits and bidirectional UDP outage.

This deliberately tests application task limits, not aioquic internal connection,
stream-buffer or kernel resource bounds. The UDP switch is a loopback fixture.
"""
import asyncio
import secrets
import struct
import time

# When executed via quic_experiment.py as __main__, import only stateless helpers
# and limit constants. Token is supplied from the owning experiment below.
from quic_experiment import cfg, frame, send, OK, DENIED, REGISTRATION_LIMIT, FORWARD_LIMIT
from aioquic.asyncio import connect


class DatagramSwitch(asyncio.DatagramProtocol):
    def __init__(self, server):
        self.server = server
        self.peer = None
        self.blocked = False
        self.dropped = 0
        self.forwarded = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if addr == self.server:
            destination = self.peer
        else:
            self.peer = addr
            destination = self.server
        if destination is None:
            return
        if self.blocked:
            self.dropped += 1
            return
        self.transport.sendto(data, destination)
        self.forwarded += 1


async def exercise(root, port, registry, registration_tasks, forward_tasks,
                   observed, inbound, register, reverse, wait_for, report, token):
    await wait_for(lambda: registry["active"] is None and not registration_tasks and not forward_tasks)
    before = len(observed)
    async with connect("127.0.0.1", port, configuration=cfg(True, root), stream_handler=inbound) as client:
        pending = []
        for _ in range(REGISTRATION_LIMIT):
            reader, writer = await client.create_stream()
            writer.write(b"x")
            pending.append((reader, writer))
        await wait_for(lambda: len(registration_tasks) == REGISTRATION_LIMIT)
        reader, writer = await client.create_stream()
        writer.write(token)
        writer.write_eof()
        assert await asyncio.wait_for(reader.readexactly(len(DENIED)), 3) == DENIED
        assert len(registration_tasks) == REGISTRATION_LIMIT
        assert registry["active"] is None and len(observed) == before
        for _, writer in pending:
            writer.write(b"x"*31)
            writer.write_eof()
        for reader, _ in pending:
            assert await asyncio.wait_for(reader.readexactly(len(DENIED)), 3) == DENIED
        await wait_for(lambda: not registration_tasks)
        assert await register(client, token) == OK
        report["registration_limit"] = REGISTRATION_LIMIT
        report["passed"].append("real incomplete registrations saturate limit; excess denied; slots recovered")

        relay = registry["active"]
        pending = []
        for _ in range(FORWARD_LIMIT):
            data = secrets.token_bytes(128)
            reader, writer = await relay.create_stream()
            writer.write(struct.pack("!I", len(data)) + data[:1])
            pending.append((reader, writer, data))
        await wait_for(lambda: len(forward_tasks) == FORWARD_LIMIT)
        reader, writer = await relay.create_stream()
        send(writer, secrets.token_bytes(64))
        assert await asyncio.wait_for(reader.read(1), 3) == b""
        assert len(forward_tasks) == FORWARD_LIMIT and len(observed) == before
        for _, writer, data in pending:
            writer.write(data[1:])
            writer.write_eof()
        for reader, _, data in pending:
            assert await asyncio.wait_for(frame(reader), 5) == data
        await wait_for(lambda: not forward_tasks)
        assert len(observed) == before + FORWARD_LIMIT
        await reverse(secrets.token_bytes(128))
        report["forward_limit"] = FORWARD_LIMIT
        report["passed"].append("real partial streams saturate admission; excess denied; binary replies and recovery verified")
    await wait_for(lambda: registry["active"] is None and not forward_tasks)

    # All datagrams of an established connection traverse a real UDP socket.
    # Stop forwarding in both directions; no fake clocks or event injection.
    loop = asyncio.get_running_loop()
    switch = DatagramSwitch(("127.0.0.1", port))
    transport, _ = await loop.create_datagram_endpoint(lambda: switch, local_addr=("127.0.0.1", 0))
    proxy_port = transport.get_extra_info("sockname")[1]
    try:
        async with connect("127.0.0.1", proxy_port, configuration=cfg(True, root), stream_handler=inbound) as client:
            assert await register(client, token) == OK
            await reverse(secrets.token_bytes(1024))
            assert switch.forwarded > 0
            before = len(observed)
            old = registry["active"]
            switch.blocked = True
            started = time.monotonic()
            # A real request attempted during blackout cannot reach the fixture.
            reader, writer = await old.create_stream()
            send(writer, secrets.token_bytes(1024))
            try:
                async with asyncio.timeout(1):
                    unexpected = await reader.read(1)
                    assert unexpected == b"", "business payload received during blackout"
            except TimeoutError:
                pass
            await wait_for(lambda: registry["active"] is None, 25)
            assert switch.dropped > 0 and len(observed) == before
            outage = time.monotonic() - started
            try:
                await reverse(b"must not forward")
            except PermissionError:
                pass
            else:
                raise AssertionError("stale registration remained usable")
        switch.blocked = False
        start = time.monotonic()
        async with connect("127.0.0.1", proxy_port, configuration=cfg(True, root), stream_handler=inbound) as client:
            assert await register(client, secrets.token_bytes(32)) == DENIED
            assert registry["active"] is None
            assert await register(client, token) == OK and registry["active"] is not old
            await reverse(secrets.token_bytes(1024))
            assert len(observed) == before + 1
            report["fresh_reconnect_and_echo_ms"] = round((time.monotonic()-start)*1000, 3)
        report["outage_until_registry_expiry_seconds"] = round(outage, 6)
        report["actual_udp_datagrams_dropped"] = switch.dropped
        report["actual_udp_datagrams_forwarded"] = switch.forwarded
        report["passed"].append("actual UDP blackout expires registration; fresh TLS and token required after restoration")
    finally:
        transport.close()
