#!/usr/bin/env python3
import asyncio

import scanner
from server_identity import server_identity


def logical_key(self):
    return server_identity(self.uri, self.protocol, self.host, self.port)


# scanner.load_sources() uses Node.key() for deduplication. Replacing it here
# makes CDN edge-IP variants collapse before TCP/Xray testing, so test slots are
# spent on different logical servers instead of copies of the same backend.
scanner.Node.key = logical_key


if __name__ == "__main__":
    asyncio.run(scanner.main())
