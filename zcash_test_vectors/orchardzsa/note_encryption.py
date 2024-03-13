#!/usr/bin/env python3
import sys;

from .asset_base import native_asset

assert sys.version_info[0] >= 3, "Python 3 required."

from chacha20poly1305 import ChaCha20Poly1305
from hashlib import blake2b

from ..output import render_args, render_tv
from ..rand import Rand

from ..orchard.pallas import Point, Scalar
from .commitments import value_commit
from ..orchard.commitments import rcv_trapdoor
from ..orchard.key_components import diversify_hash, prf_expand, FullViewingKey, SpendingKey
from..orchard.note_encryption import kdf_orchard, prf_ock_orchard, OrchardKeyAgreement, OrchardSym
from .note import OrchardZSANote, OrchardZSANotePlaintext
from ..orchard.utils import to_scalar


# https://zips.z.cash/protocol/nu5.pdf#saplingandorchardencrypt
class OrchardZSANoteEncryption(object):
    def __init__(self, rand):
        self._rand = rand

    def encrypt(self, note: OrchardZSANote, memo, pk_d_new, g_d_new, cv_new, cm_new, ovk=None):
        np = note.note_plaintext(memo)
        esk = OrchardKeyAgreement.esk(np.rseed, note.rho)
        p_enc = bytes(np)

        epk = OrchardKeyAgreement.derive_public(esk, g_d_new)
        ephemeral_key = bytes(epk)
        shared_secret = OrchardKeyAgreement.agree(esk, pk_d_new)
        k_enc = kdf_orchard(shared_secret, ephemeral_key)
        c_enc = OrchardSym.encrypt(k_enc, p_enc)

        if ovk is None:
            ock = OrchardSym.k(self._rand)
            op = self._rand.b(64)
        else:
            cv = bytes(cv_new)
            cmx = bytes(cm_new.extract())
            ock = prf_ock_orchard(ovk, cv, cmx, ephemeral_key)
            op = bytes(pk_d_new) + bytes(esk)

        c_out = OrchardSym.encrypt(ock, op)

        self.esk = esk
        self.shared_secret = shared_secret
        self.k_enc = k_enc
        self.p_enc = p_enc
        self.ock = ock
        self.op = op

        return TransmittedZSANoteCipherText(
            epk, c_enc, c_out
        )

class TransmittedZSANoteCipherText(object):
    def __init__(self, epk, c_enc, c_out):
        self.epk = epk
        self.c_enc = c_enc
        self.c_out = c_out

    def decrypt_using_ivk(self, ivk: Scalar, rho, cm_star):
        epk = self.epk
        if epk is None:
            return None

        shared_secret = OrchardKeyAgreement.agree(ivk, epk)
        # The protocol spec says to take `ephemeral_key` as input to decryption
        # and to decode epk from it. That is required for consensus compatibility
        # in Sapling decryption before ZIP 216, but the reverse is okay here
        # because Pallas points have no non-canonical encodings.
        ephemeral_key = bytes(epk)
        k_enc = kdf_orchard(shared_secret, ephemeral_key)
        p_enc = OrchardSym.decrypt(k_enc, self.c_enc)
        if p_enc is None:
            return None

        np = OrchardZSANotePlaintext.from_bytes(p_enc)

        g_d = diversify_hash(np.d)

        esk = OrchardKeyAgreement.esk(np.rseed, rho)
        if OrchardKeyAgreement.derive_public(esk, g_d) != epk:
            return None

        pk_d = OrchardKeyAgreement.derive_public(ivk, g_d)
        note = OrchardZSANote(np.d, pk_d, np.v, np.asset, rho, np.rseed)

        cm = note.note_commitment()
        if cm is None:
            return None
        if cm.extract() != cm_star:
            return None

        return (note, np.memo)

    def decrypt_using_ovk(self, ovk, rho, cv, cm_star):
        # The protocol spec says to take `ephemeral_key` as input to decryption
        # and to decode epk from it. That is required for consensus compatibility
        # in Sapling decryption before ZIP 216, but the reverse is okay here
        # because Pallas points have no non-canonical encodings.
        ephemeral_key = bytes(self.epk)
        ock = prf_ock_orchard(ovk, bytes(cv), bytes(cm_star), ephemeral_key)
        op = OrchardSym.decrypt(ock, self.c_out)
        if op is None:
            return None

        (pk_d_star, esk) = (op[0:32], op[32:64])
        esk = Scalar.from_bytes(esk)
        pk_d = Point.from_bytes(pk_d_star)
        if bytes(pk_d) != pk_d_star:
            return None

        shared_secret = OrchardKeyAgreement.agree(esk, pk_d)
        k_enc = kdf_orchard(shared_secret, ephemeral_key)
        p_enc = OrchardSym.decrypt(k_enc, self.c_enc)
        if p_enc is None:
            return None

        np = OrchardZSANotePlaintext.from_bytes(p_enc)
        if OrchardKeyAgreement.esk(np.rseed, rho) != esk:
            return None
        g_d = diversify_hash(np.d)
        note = OrchardZSANote(np.d, pk_d, np.v, np.asset, rho, np.rseed)

        cm = note.note_commitment()
        if cm is None:
            return None
        if cm.extract() != cm_star:
            return None

        if OrchardKeyAgreement.derive_public(esk, g_d) != self.epk:
            return None

        return (note, np.memo)


def main():
    args = render_args()

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
        sender_ovk = rand.b(32)

        receiver_sk = SpendingKey(rand.b(32))
        receiver_fvk = FullViewingKey.from_spending_key(receiver_sk)
        ivk = receiver_fvk.ivk()
        d = receiver_fvk.default_d()
        pk_d = receiver_fvk.default_pkd()
        g_d = diversify_hash(d)

        is_native = i < 10
        asset_point = native_asset() if is_native else Point.rand(rand)
        asset_bytes = bytes(asset_point)
        rseed = rand.b(32)
        memo = b'\xff' + rand.b(511)

        np = OrchardZSANotePlaintext(d, rand.u64(), rseed, asset_bytes, memo)

        rcv = rcv_trapdoor(rand)
        cv = value_commit(rcv, Scalar(np.v), asset_point)

        rho = np.dummy_nullifier(rand)
        note = OrchardZSANote(d, pk_d, np.v, asset_bytes, rho, rseed)
        cm = note.note_commitment()

        ne = OrchardZSANoteEncryption(rand)

        transmitted_note_ciphertext = ne.encrypt(note, memo, pk_d, g_d, cv, cm, sender_ovk)

        (note_using_ivk, memo_using_ivk) = transmitted_note_ciphertext.decrypt_using_ivk(
            Scalar(ivk.s), rho, cm.extract()
        )
        (note_using_ovk, memo_using_ovk) = transmitted_note_ciphertext.decrypt_using_ovk(
            sender_ovk, rho, cv, cm.extract()
        )

        assert(note_using_ivk == note_using_ovk)
        assert(memo_using_ivk == memo_using_ovk)
        assert(note_using_ivk == note)
        assert(memo_using_ivk == memo)

        test_vectors.append({
            'incoming_viewing_key': receiver_fvk.dk + bytes(ivk),
            'ovk': sender_ovk,
            'default_d': d,
            'default_pk_d': bytes(pk_d),
            'v': np.v,
            'rseed': note.rseed,
            'asset': asset_bytes,
            'memo': np.memo,
            'cv_net': bytes(cv),
            'rho': bytes(rho),
            'cmx': bytes(cm.extract()),
            'esk': bytes(ne.esk),
            'ephemeral_key': bytes(transmitted_note_ciphertext.epk),
            'shared_secret': bytes(ne.shared_secret),
            'k_enc': ne.k_enc,
            'p_enc': ne.p_enc,
            'c_enc': transmitted_note_ciphertext.c_enc,
            'ock': ne.ock,
            'op': ne.op,
            'c_out': transmitted_note_ciphertext.c_out,
        })

    render_tv(
        args,
        'orchard_note_encryption',
        (
            ('incoming_viewing_key', '[u8; 64]'),
            ('ovk', '[u8; 32]'),
            ('default_d', '[u8; 11]'),
            ('default_pk_d', '[u8; 32]'),
            ('v', 'u64'),
            ('rseed', '[u8; 32]'),
            ('asset', '[u8; 32]'),
            ('memo', '[u8; 512]'),
            ('cv_net', '[u8; 32]'),
            ('rho', '[u8; 32]'),
            ('cmx', '[u8; 32]'),
            ('esk', '[u8; 32]'),
            ('ephemeral_key', '[u8; 32]'),
            ('shared_secret', '[u8; 32]'),
            ('k_enc', '[u8; 32]'),
            ('p_enc', '[u8; 596]'),
            ('c_enc', '[u8; 612]'),
            ('ock', '[u8; 32]'),
            ('op', '[u8; 64]'),
            ('c_out', '[u8; 80]'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
