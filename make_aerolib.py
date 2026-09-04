#!/usr/bin/env python
'''

make_aerolib.py -- (re)build aerolib.csv from one or more plain symbol name lists.

A Sony NID is the first 8 bytes of

    sha1(name + 518D64A635DED8C1E6B039B1C3E55230)

read big-endian, re-packed little-endian, base64'd, truncated to 11 characters,
with '/' rewritten as '-' (Sony's alphabet is A-Za-z0-9+-).

Usage:

    python make_aerolib.py ps5_symbols.txt [more_symbols.txt ...]

Existing aerolib.csv entries are kept, so running this only ever adds coverage.
Every row is verified to actually hash back to its own NID before being written.

'''

from __future__ import print_function

import base64
import hashlib
import os
import struct
import sys

SALT = bytes(bytearray.fromhex('518D64A635DED8C1E6B039B1C3E55230'))

HERE    = os.path.dirname(os.path.abspath(__file__))
AEROLIB = os.path.join(HERE, 'aerolib.csv')


def nid(name):

    digest = hashlib.sha1(name.encode('utf8') + SALT).digest()
    value  = struct.unpack('>Q', digest[:8])[0]
    return base64.b64encode(struct.pack('<Q', value))[:11].decode('ascii').replace('/', '-')


def read_csv(path):

    entries = {}

    if not os.path.exists(path):
        return entries

    with open(path, 'r') as database:
        for line in database:
            key, _, value = line.rstrip('\r\n').partition(' ')
            if key and value:
                entries[key] = value

    return entries


def main(argv):

    if len(argv) < 2:
        print(__doc__)
        return 1

    entries = read_csv(AEROLIB)
    print('# %-8i existing rows in aerolib.csv' % len(entries))

    for path in argv[1:]:
        added   = 0
        skipped = 0

        with open(path, 'r') as source:
            for line in source:
                name = line.strip()

                # NIDs are hashed over C identifiers -- anything with whitespace
                # in it is contamination, not a symbol
                if not name or ' ' in name or '\t' in name:
                    skipped += 1
                    continue

                key = nid(name)
                if key not in entries:
                    added += 1
                entries[key] = name

        print('# %-8i added from %s (%i lines ignored)' % (added, path, skipped))

    # Drop anything that does not survive a round trip
    clean = dict((key, value) for key, value in entries.items()
                 if ' ' not in value and nid(value) == key)

    if len(clean) != len(entries):
        print('# %-8i rows dropped (name does not hash to its NID)' % (len(entries) - len(clean)))

    with open(AEROLIB, 'w') as database:
        for key in sorted(clean, key=lambda k: clean[k]):
            database.write('%s %s\n' % (key, clean[key]))

    print('# %-8i rows written to %s' % (len(clean), AEROLIB))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
