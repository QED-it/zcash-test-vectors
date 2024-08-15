import struct

from .orchard.key_components import FullViewingKey, SpendingKey
from .orchard_zsa.key_components import IssuanceKeys
from .orchard.pallas import Point
from .orchard_zsa.asset_base import zsa_value_base, asset_digest, encode_asset_id, get_random_unicode_bytes
from .zc_utils import write_compact_size
from .transaction import (
    NOTEENCRYPTION_AUTH_BYTES, ZC_SAPLING_ENCPLAINTEXT_SIZE,
    OrchardActionBase, TransactionBase,
)

NU7_VERSION_GROUP_ID = 0x124A69F8
NU7_TX_VERSION = 7

# Orchard ZSA note values
ZC_ORCHARD_ZSA_ASSET_SIZE = 32
ZC_ORCHARD_ZSA_ENCPLAINTEXT_SIZE = ZC_SAPLING_ENCPLAINTEXT_SIZE + ZC_ORCHARD_ZSA_ASSET_SIZE
ZC_ORCHARD_ZSA_ENCCIPHERTEXT_SIZE = ZC_ORCHARD_ZSA_ENCPLAINTEXT_SIZE + NOTEENCRYPTION_AUTH_BYTES


class OrchardZSAActionDescription(OrchardActionBase):
    def __init__(self, rand):
        super().__init__(ZC_ORCHARD_ZSA_ENCCIPHERTEXT_SIZE, rand)


class AssetBurnDescription(object):
    def __init__(self, rand):
        isk = IssuanceKeys(rand.b(32))
        desc_size = rand.u32() % 512 + 1
        desc_bytes = get_random_unicode_bytes(desc_size, rand)
        asset_digest_bytes = asset_digest(encode_asset_id(isk.ik, desc_bytes))
        self.assetBase: Point = zsa_value_base(asset_digest_bytes)
        self.valueBurn = rand.u64()

    def __bytes__(self):
        return bytes(self.assetBase) + struct.pack('<Q', self.valueBurn)


class IssueActionDescription(object):
    def __init__(self, rand, ik):
        self.assetDescSize = rand.u32() % 512 + 1
        self.asset_desc = get_random_unicode_bytes(self.assetDescSize, rand)
        self.vNotes = []
        for _ in range(rand.u8() % 5):
            self.vNotes.append(IssueNote(rand, ik, self.asset_desc))
        self.flagsIssuance = rand.u8() & 1  # Only one bit is reserved for the finalize flag currently

    def __bytes__(self):
        ret = b''

        ret += write_compact_size(self.assetDescSize)
        ret += bytes(self.asset_desc)
        ret += write_compact_size(len(self.vNotes))
        if len(self.vNotes) > 0:
            for note in self.vNotes:
                ret += bytes(note)
        ret += struct.pack('B', self.flagsIssuance)

        return ret


class IssueNote(object):
    def __init__(self, rand, ik, asset_desc):
        fvk_r = FullViewingKey.from_spending_key(SpendingKey(rand.b(32)))
        self.recipient = fvk_r.default_d() + bytes(fvk_r.default_pkd())
        self.value = rand.u64()
        asset_digest_bytes = asset_digest(encode_asset_id(ik, asset_desc))
        self.assetBase = zsa_value_base(asset_digest_bytes)
        self.rho = Point.rand(rand).extract()
        self.rseed = rand.b(32)

    def __bytes__(self):
        ret = b''
        ret += bytes(self.recipient)
        ret += struct.pack('<Q', self.value)
        ret += bytes(self.assetBase)
        ret += bytes(self.rho)
        ret += self.rseed

        return ret


class TransactionZSA(TransactionBase):
    def __init__(self, rand, consensus_branch_id, have_orchard_zsa=True, have_burn=True, have_issuance=True):

        # We cannot have burns without an OrchardZSA bundle.
        assert have_orchard_zsa or not have_burn

        # All the Transparent and Sapling Transaction Fields are initialized in the super (TransactionBase) class.
        super().__init__(rand, have_orchard_zsa)

        # Common Transaction Fields
        self.nVersionGroupId = NU7_VERSION_GROUP_ID
        self.nConsensusBranchId = consensus_branch_id

        # OrchardZSA Transaction Fields
        if have_orchard_zsa:
            for _ in range(rand.u8() % 5):
                self.vActionsOrchard.append(OrchardZSAActionDescription(rand))
            self.flagsOrchard = (self.flagsOrchard & 7) | 4  # Three flag bits are defined, we set enableZSA to true.
            if self.is_coinbase():
                self.flagsOrchard &= 2  # set enableSpendsOrchard = 0

        # OrchardZSA Burn Fields
        self.vAssetBurnOrchardZSA = []
        if have_burn:
            for _ in range(rand.u8() % 5):
                self.vAssetBurnOrchardZSA.append(AssetBurnDescription(rand))

        # OrchardZSA Issuance Fields
        self.vIssueActions = []
        if have_issuance:
            self.ik = IssuanceKeys(rand.b(32)).ik
            for _ in range(rand.u8() % 5):
                self.vIssueActions.append(IssueActionDescription(rand, self.ik))
            self.issueAuthSig = rand.b(64)

    @staticmethod
    def version_bytes(self):
        return NU7_TX_VERSION | (1 << 31)

    def orchard_zsa_burn_field_bytes(self):
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
            ret += self.ik
            ret += bytes(self.issueAuthSig)
        return ret

    def __bytes__(self):
        ret = b''

        # Fields that are in TransactionBase: Common, Transparent, Sapling, most Orchard
        ret += super().__bytes__(self.version_bytes(), self.nVersionGroupId, self.nConsensusBranchId)

        # OrchardZSA remaining Transaction Fields (if the Orchard bundle exists)
        if len(self.vActionsOrchard) > 0:
            ret += self.orchard_zsa_burn_field_bytes()
            ret += bytes(self.bindingSigOrchard)

        # OrchardZSA Issuance Fields
        ret += self.issuance_field_bytes()

        return ret
