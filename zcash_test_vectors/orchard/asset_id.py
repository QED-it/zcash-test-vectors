#!/usr/bin/env python3
import sys;

assert sys.version_info[0] >= 3, "Python 3 required."

import string

from ..orchard.group_hash import group_hash
from ..output import render_args, render_tv, option


def asset_id(key, description):
    return group_hash(b"z.cash:Orchard-cv", key + description)


def main():
    args = render_args()

    from zcash_test_vectors.rand import Rand
    from zcash_test_vectors.orchard.key_components import SpendingKey
    from zcash_test_vectors.orchard.key_components import FullViewingKey
    from random import Random

    rng = Random(0xabad533d)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rand = Rand(randbytes)

    test_vectors = []
    for i in range(0, 20):
        sk = SpendingKey(rand.b(32))
        fvk = FullViewingKey.from_spending_key(sk)

        key_bytes = bytes(fvk.ivk())
        description = ''.join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(512))
        description_bytes = description.encode("UTF-8")
        asset = asset_id(key_bytes, description_bytes)

        test_vectors.append({
                'key': key_bytes,
                'description': description_bytes,
                'asset_id': bytes(asset),
            })

    render_tv(
        args,
        'orchard_asset_id',
        (
            ('key', '[u8; 32]'),
            ('description', '[u8; 512]'),
            ('asset_id', '[u8; 32]'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
