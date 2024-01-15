#!/usr/bin/env python3
import sys;

from zcash_test_vectors.bip340_reference import pubkey_gen, schnorr_sign, hash_sha256
from zcash_test_vectors.orchard.key_components import IssuanceAuthorizingKey

from ..output import render_args, render_tv

assert sys.version_info[0] >= 3, "Python 3 required."

def main():
    args = render_args()

    from random import Random
    from ..rand import Rand

    rng = Random(0xabad533d)

    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)

    rand = Rand(randbytes)

    test_vectors = []
    for i in range(0, 10):
        isk = IssuanceAuthorizingKey(rand.b(32))
        ik = isk.ik
        msg = rand.b(612)
        aux_rand = b'\0' * 32
        sig = schnorr_sign(hash_sha256(msg), bytes(isk.isk), aux_rand)

        test_vectors.append({
            'isk': bytes(isk.isk),
            'ik': bytes(ik),
            'msg': msg,
            'sig': sig,
        })

    render_tv(
        args,
        'zsa_issuance_auth_sig',
        (
            ('isk', '[u8; 32]'),
            ('ik', '[u8; 32]'),
            ('msg', '[u8; 612]'),
            ('sig', '[u8; 64]'),
        ),
        test_vectors,
    )

if __name__ == '__main__':
    main()


