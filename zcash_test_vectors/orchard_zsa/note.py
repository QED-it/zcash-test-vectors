import struct

from .asset_base import native_asset
from .commitments import note_commit
from ..orchard.key_components import diversify_hash, derive_nullifier, prf_expand, FullViewingKey, SpendingKey
from ..orchard.note import OrchardNote
from ..orchard.pallas import Point, Scalar
from ..orchard.utils import to_base, to_scalar
from ..utils import leos2bsp


class OrchardZSANote(OrchardNote):
    def __init__(self, d, pk_d, v, asset, rho, rseed):
        OrchardNote.__init__(self, d, pk_d, v, rho, rseed)
        self.asset = asset

    def __eq__(self, other):
        if other is None:
            return False
        return (
                OrchardNote.__eq__(self, other) and
                self.asset == other.asset
        )

    def note_commitment(self):
        g_d = diversify_hash(self.d)
        # asset = self.asset and leos2bsp(self.asset)
        return note_commit(self.rcm, leos2bsp(bytes(g_d)), leos2bsp(bytes(self.pk_d)), self.v, leos2bsp(bytes(self.asset)), self.rho, self.psi)

    def note_plaintext(self, memo):
        return OrchardZSANotePlaintext(self.d, self.v, self.rseed, self.asset, memo)

# https://zips.z.cash/protocol/nu5.pdf#notept
class OrchardZSANotePlaintext(object):
    def __init__(self, d, v, rseed, asset, memo):
        self.leadbyte = bytes.fromhex('03')
        self.d = d
        self.v = v
        self.asset = asset
        self.rseed = rseed
        self.memo = memo
    
    @staticmethod
    def from_bytes(buf):
        leadbyte = buf[0]
        if leadbyte == 2:
            return OrchardZSANotePlaintext._from_bytes_orchard(buf)
        if leadbyte == 3:
            return OrchardZSANotePlaintext._from_bytes_zsa(buf)
        raise "invalid lead byte"

    @staticmethod
    def _from_bytes_orchard(buf):
        return OrchardZSANotePlaintext(
            buf[1:12],    # d
            struct.unpack('<Q', buf[12:20])[0],  # v
            buf[20:52],   # rseed
            native_asset(),         # asset
            buf[52:564],  # memo
        )

    @staticmethod
    def _from_bytes_zsa(buf):
        return OrchardZSANotePlaintext(
            buf[1:12],   # d
            struct.unpack('<Q', buf[12:20])[0],  # v
            buf[20:52],  # rseed
            buf[52:84],  # asset
            buf[84:596]  # memo
        )

    def __bytes__(self):
        return (
            self.leadbyte +
            self.d +
            struct.pack('<Q', self.v) +
            self.rseed +
            self.asset +
            self.memo
        )

    def dummy_nullifier(self, rand):
        sk = SpendingKey(rand.b(32))
        fvk = FullViewingKey.from_spending_key(sk)
        pk_d = fvk.default_pkd()
        d = fvk.default_d()

        v = 0
        rseed = rand.b(32)
        rho = Point.rand(rand).extract()

        note = OrchardZSANote(d, pk_d, v, native_asset(), rho, rseed)
        cm = note.note_commitment()
        return derive_nullifier(fvk.nk, rho, note.psi, cm)
