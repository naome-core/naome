"""Bounded TCP delay for the disposable devnet; no protocol decoding or authority."""
import asyncio
import concurrent.futures
import threading


def endpoint(address):
    fields = address.split("/")
    if len(fields) != 5 or fields[1] not in ("ip4", "ip6") or fields[3] != "tcp":
        raise ValueError("literal TCP endpoint required")
    return fields[2], int(fields[4])


class Proxy:
    def __init__(self, address, listen, delay_ms):
        if not 0 <= delay_ms <= 1000:
            raise ValueError("delay must be 0..1000 milliseconds")
        self.front = endpoint(address)
        self.back = endpoint(listen)
        self.delay = delay_ms / 1000
        self.loop = asyncio.new_event_loop()
        self.tasks = set()
        self.open_writers = set()
        self.started = concurrent.futures.Future()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        self.started.result(timeout=5)

    def run(self):
        asyncio.set_event_loop(self.loop)
        try:
            server = self.loop.run_until_complete(asyncio.start_server(self.accept, *self.front, limit=32_768, backlog=16))
            self.started.set_result(True)
            self.loop.run_forever()
            server.close()
            self.loop.run_until_complete(server.wait_closed())
            for writer in list(self.open_writers):
                writer.close()
            for task in list(self.tasks):
                task.cancel()
            self.loop.run_until_complete(asyncio.gather(*self.tasks, return_exceptions=True))
        except Exception as error:
            if not self.started.done():
                self.started.set_exception(error)
        finally:
            self.loop.close()

    async def accept(self, reader, writer):
        if len(self.tasks) >= 16:
            writer.close()
            return
        task = asyncio.current_task()
        self.tasks.add(task)
        self.open_writers.add(writer)
        peer_writer = None
        pumps = []
        try:
            peer_reader, peer_writer = await asyncio.wait_for(asyncio.open_connection(*self.back, limit=32_768), timeout=3)
            self.open_writers.add(peer_writer)

            async def copy(source, target):
                while True:
                    data = await source.read(32_768)
                    if not data:
                        return
                    if self.delay:
                        await asyncio.sleep(self.delay)
                    target.write(data)
                    await target.drain()

            pumps = [asyncio.create_task(copy(reader, peer_writer)), asyncio.create_task(copy(peer_reader, writer))]
            await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        except (OSError, asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            for item in (writer, peer_writer):
                if item is not None:
                    item.close()
                    self.open_writers.discard(item)
            self.tasks.discard(task)

    def close(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("proxy shutdown exceeded bound")
