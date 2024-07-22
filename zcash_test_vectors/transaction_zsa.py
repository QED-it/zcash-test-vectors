import struct

from .orchard.key_components import FullViewingKey, SpendingKey
from .orchard_zsa.key_components import IssuanceKeys
from .orchard.pallas import (
    Fp as PallasBase,
    Point
)
from .orchard.sinsemilla import group_hash as pallas_group_hash
from .orchard_zsa.asset_base import zsa_value_base, asset_digest, encode_asset_id, get_random_unicode_bytes
from .utils import leos2ip
from .zc_utils import write_compact_size
from .transaction import (
    MAX_MONEY, NOTEENCRYPTION_AUTH_BYTES,
    ZC_SAPLING_ENCPLAINTEXT_SIZE, ZC_SAPLING_OUTCIPHERTEXT_SIZE,
    RedPallasSignature,
    TransactionBase,
)

NU7_VERSION_GROUP_ID = 0x124A69F8
NU7_TX_VERSION = 7

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

        isk = IssuanceKeys(rand.b(32))
        desc_size = rand.u32() % 512 + 1
        desc_bytes = get_random_unicode_bytes(desc_size, rand)
        self.assetBase : Point = zsa_value_base(asset_digest(encode_asset_id(isk.ik, desc_bytes)))
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
        self.flagsIssuance = rand.u8() & 1    # Only one bit is reserved for the finalize flag currently

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
        self.assetBase = zsa_value_base(asset_digest(encode_asset_id(ik, asset_desc)))
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
    def __init__(self, rand, consensus_branch_id, have_orchard_zsa = True, have_burn = True, have_issuance = True):

        # Since burn is part of the OrchardZSA bundle, ensure that there are no burn fields
        # when there are no OrchardZSA fields
        assert have_orchard_zsa or not have_burn

        # All the Transparent and Sapling Transaction Fields are initialized in the super (TransactionBase) class.
        super().__init__(rand)

        # Common Transaction Fields
        self.nVersionGroupId = NU7_VERSION_GROUP_ID
        self.nConsensusBranchId = consensus_branch_id

        # Orchard-ZSA Transaction Fields
        self.vActionsOrchardZSA = []
        if have_orchard_zsa:
            for _ in range(rand.u8() % 5):
                self.vActionsOrchardZSA.append(OrchardZSAActionDescription(rand))
            self.flagsOrchardZSA = rand.u8() & 7 # Only three flag bits are currently defined.
            self.flagsOrchardZSA |= 4  # Setting enableZSAs to true for these tests
            if self.is_coinbase():
                # set enableSpendsOrchard = 0
                self.flagsOrchardZSA &= 2
            self.valueBalanceOrchardZSA = rand.u64() % (MAX_MONEY + 1)
            self.anchorOrchardZSA = PallasBase(leos2ip(rand.b(32)))
            self.proofsOrchardZSA = rand.b(rand.u8() + 32) # Proof will always contain at least one element
            self.bindingSigOrchardZSA = RedPallasSignature(rand)

        else:
            # If valueBalanceOrchard is not present in the serialized transaction, then
            # v^balanceOrchard is defined to be 0.
            self.valueBalanceOrchardZSA = 0

        # OrchardZSA Burn Fields
        self.vAssetBurnOrchardZSA = []
        if have_burn:
            for _ in range(rand.u8() % 5):
                self.vAssetBurnOrchardZSA.append(AssetBurnDescription(rand))

        # ZSA Issuance Fields
        self.vIssueActions = []
        if have_issuance:
            self.ik = IssuanceKeys(rand.b(32)).ik
            for _ in range(rand.u8() % 5):
                self.vIssueActions.append(IssueActionDescription(rand, self.ik))
            self.issueAuthSig = rand.b(64)

    def version_bytes(self):
        return NU7_TX_VERSION | (1 << 31)

    def orchard_zsa_transfer_field_bytes(self):
        ret = b''
        ret += write_compact_size(len(self.vActionsOrchardZSA))
        if len(self.vActionsOrchardZSA) > 0:
            # Not explicitly gated in the protocol spec, but if the gate
            # were inactive then these loops would be empty by definition.
            for desc in self.vActionsOrchardZSA:
                ret += bytes(desc) # Excludes spendAuthSig
            ret += struct.pack('B', self.flagsOrchardZSA)
            ret += struct.pack('<Q', self.valueBalanceOrchardZSA)
            ret += bytes(self.anchorOrchardZSA)
            ret += write_compact_size(len(self.proofsOrchardZSA))
            ret += self.proofsOrchardZSA
            for desc in self.vActionsOrchardZSA:
                ret += bytes(desc.spendAuthSig)

            # OrchardZSA Burn Fields
            ret += self.orchard_zsa_burn_field_bytes()

            ret += bytes(self.bindingSigOrchardZSA)
        return ret

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

        # Common Transaction Fields
        ret += struct.pack('<I', self.version_bytes())
        ret += struct.pack('<I', self.nVersionGroupId)
        ret += struct.pack('<I', self.nConsensusBranchId)
        ret += struct.pack('<I', self.nLockTime)
        ret += struct.pack('<I', self.nExpiryHeight)

        # Fields that are in TransactionBase: Transparent, Sapling
        ret += super().__bytes__()

        # OrchardZSA Transaction Fields
        ret += self.orchard_zsa_transfer_field_bytes()

        # ZSA Issuance Fields
        ret += self.issuance_field_bytes()

        return ret