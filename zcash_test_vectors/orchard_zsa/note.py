import struct

from .asset_base import native_asset
from .commitments import note_commit
from ..orchard.key_components import diversify_hash
from ..orchard.note import OrchardNote, OrchardNotePlaintext
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
class OrchardZSANotePlaintext(OrchardNotePlaintext):
    def __init__(self, d, v, rseed, asset, memo):
        OrchardNotePlaintext.__init__(self, d, v, rseed, memo)
        self.leadbyte = bytes.fromhex('03')
        self.asset = asset

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
            OrchardNotePlaintext.__bytes__(self)[:-512] +
            self.asset +
            self.memo
        )
