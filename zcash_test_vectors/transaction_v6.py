import struct

from .orchard.pallas import Fp as PallasBase
from .orchard.sinsemilla import group_hash as pallas_group_hash
from .sapling.jubjub import Fq
from .utils import leos2ip
from .zc_utils import write_compact_size
from .transaction import (
    MAX_MONEY, NOTEENCRYPTION_AUTH_BYTES, TX_EXPIRY_HEIGHT_THRESHOLD,
    ZC_SAPLING_ENCPLAINTEXT_SIZE, ZC_SAPLING_OUTCIPHERTEXT_SIZE,
    RedPallasSignature,
    TransactionV5,
)

NU6_VERSION_GROUP_ID = 0x124A69F8
NU6_TX_VERSION = 6

# Orchard ZSA note values
ZC_ORCHARD_ZSA_ASSET_SIZE = 32
ZC_ORCHARD_ZSA_ENCPLAINTEXT_SIZE = ZC_SAPLING_ENCPLAINTEXT_SIZE + ZC_ORCHARD_ZSA_ASSET_SIZE
ZC_ORCHARD_ZSA_ENCCIPHERTEXT_SIZE = ZC_ORCHARD_ZSA_ENCPLAINTEXT_SIZE + NOTEENCRYPTION_AUTH_BYTES

class OrchardZSAActionDescription(object):
    def __init__(self, rand):
        # We don't need to take account of whether this is a coinbase transaction,
        # because we're only generating random fields.
        self.cv = pallas_group_hash(b'TVRandPt', rand.b(32))
        self.nullifier = PallasBase(leos2ip(rand.b(32)))
        self.rk = pallas_group_hash(b'TVRandPt', rand.b(32))
        self.cmx = PallasBase(leos2ip(rand.b(32)))
        self.ephemeralKey = pallas_group_hash(b'TVRandPt', rand.b(32))
        self.encCiphertext = rand.b(ZC_ORCHARD_ZSA_ENCCIPHERTEXT_SIZE)
        self.outCiphertext = rand.b(ZC_SAPLING_OUTCIPHERTEXT_SIZE)
        self.spendAuthSig = RedPallasSignature(rand)

    def __bytes__(self):
        return (
                bytes(self.cv) +
                bytes(self.nullifier) +
                bytes(self.rk) +
                bytes(self.cmx) +
                bytes(self.ephemeralKey) +
                self.encCiphertext +
                self.outCiphertext
        )

class AssetBurnDescription(object):
    def __init__(self, rand):
        self.AssetBase = PallasBase(leos2ip(rand.b(32)))
        _temp = rand.u64()
        self.valueBurn = _temp if _temp != 0 else _temp + 1

    def __bytes__(self):
        return bytes(self.AssetBase) + struct.pack('<Q', self.valueBurn)

class IssueActionDescription(object):
    def __init__(self, rand):
        self.assetDescSize = rand.u32() % 512 + 1
        if self.assetDescSize > 0:
            self.asset_desc = rand.b(self.assetDescSize)
        self.vNotes = []
        for _ in range(rand.u8() % 5):
            self.vNotes.append(rand.b(596))    # TODO: VA: Do we need a separate IssueNote class?
        self.flagsIssuance = rand.u8() & 1    # Only one bit is reserved for the finalize flag currently

    def __bytes__(self):
        ret = b''

        ret += struct.pack('B', int(self.assetDescSize / 256)) + struct.pack('B',self.assetDescSize % 256)
        ret += bytes(self.asset_desc)
        ret += write_compact_size(len(self.vNotes))
        if len(self.vNotes) > 0:
            for note in self.vNotes:
                ret += note
        ret += struct.pack('B', self.flagsIssuance)

        return ret

class TransactionV6(TransactionV5):
    def __init__(self, rand, consensus_branch_id):

        super().__init__(rand, consensus_branch_id)

        flip_coins = rand.u8()

        have_orchard_zsa = len(self.vActionsOrchard) != 0
        have_burn = have_orchard_zsa and (flip_coins >> 5) % 2
        have_issuance = (flip_coins >> 6) % 2

        # Common Transaction Fields that need to be updated from the TxV5 definitions
        self.nVersionGroupId = NU6_VERSION_GROUP_ID

        # Orchard-ZSA Transaction Fields
        self.vActionsOrchard = []
        if have_orchard_zsa:
            for _ in range(rand.u8() % 5):
                self.vActionsOrchard.append(OrchardZSAActionDescription(rand))
            self.flagsOrchard = rand.u8() & 7 # Only three flag bits are currently defined.
        else:
            # If valueBalanceOrchard is not present in the serialized transaction, then
            # v^balanceOrchard is defined to be 0.
            self.valueBalanceOrchard = 0

        # OrchardZSA Burn Fields
        self.vAssetBurnOrchardZSA = []
        if have_burn:
            for _ in range(rand.u8() % 5):
                self.vAssetBurnOrchardZSA.append(AssetBurnDescription(rand))

        # ZSA Issuance Fields
        self.vIssueActions = []
        if have_issuance:
            for _ in range(rand.u8() % 5):
                self.vIssueActions.append(IssueActionDescription(rand))
            self.ik = rand.b(32)
            self.issueAuthSig = rand.b(64)

    def version_bytes(self):
        return NU6_TX_VERSION | (1 << 31)

    def burn_field_bytes(self):
        ret = b''
        ret += write_compact_size(len(self.vAssetBurnOrchardZSA))
        if len(self.vAssetBurnOrchardZSA) > 0:
            for desc in self.vAssetBurnOrchardZSA:
                ret += bytes(desc)
        return ret

    def issuance_field_bytes(self):
        ret = b''
        ret += write_compact_size(len(self.vIssueActions))
        if len(self.vIssueActions) > 0:
            for desc in self.vIssueActions:
                ret += bytes(desc)
            ret += bytes(self.ik)
            ret += bytes(self.issueAuthSig)
        return ret

    def __bytes__(self):
        ret = b''

        # Common Transaction Fields
        ret += self.common_txn_field_bytes()

        # Transparent Transaction Fields
        ret += self.transparent_txn_field_bytes()

        # Sapling Transaction Fields
        ret += self.sapling_txn_field_bytes()

        # OrchardZSA Transaction Fields
        ret += self.orchard_txn_field_bytes()

        # OrchardZSA Burn Fields
        ret += self.burn_field_bytes()

        # ZSA Issuance Fields
        ret += self.issuance_field_bytes()

        return ret