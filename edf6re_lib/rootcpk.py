"""Read-only access to files inside the game's Root.cpk (cpk.py + crilayla.py). Nothing here writes to the game directory.

Written for this project; MIT license (see LICENSE).
"""
from __future__ import annotations

import os

from . import cpk
from . import crilayla


class Game:
    """Read-only view of the game's Root.cpk (or another of its archives: Chunk01.cpk / Chunk02.cpk hold more of the
    objects)."""

    def __init__(self, root: str, archive: str = 'Root.cpk') -> None:
        self.root = root
        self.cpk = cpk.Cpk(os.path.join(root, archive))
        # The index by its upper-cased (folder, name), the first entry of a spelling kept: a read was a scan of the
        # whole index (tens of thousands of entries) every time.
        self._keys: dict[tuple[str, str], tuple[str, str]] = {}
        for k in self.cpk.index:
            self._keys.setdefault((k[0].upper(), k[1].upper()), k)

    def _key(self, folder: str, name: str) -> tuple[str, str]:
        try:
            return self._keys[folder.upper(), name.upper()]
        except KeyError:
            raise KeyError(f'{folder}/{name}') from None

    def names(self, folder: str) -> list[str]:
        """The file names in `folder` (case-insensitive), sorted."""
        return sorted(n for d, n in self.cpk.index if d.upper() == folder.upper())

    def read(self, folder: str, name: str) -> bytes:
        """The file folder/name (case-insensitive), decompressed."""
        e = self.cpk.index[self._key(folder, name)]
        with open(self.cpk.path, 'rb') as h:
            h.seek(self.cpk.base + int(e['FileOffset']))
            data = h.read(int(e['FileSize']))
        return crilayla.decompress(data) if int(e['ExtractSize']) != int(e['FileSize']) else data
