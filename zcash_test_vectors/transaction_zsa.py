import struct

from .orchard.pallas import Fp as PallasBase
from .orchard.sinsemilla import group_hash as pallas_group_hash
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

class TransactionZSA(TransactionBase):
    def __init__(self, rand, consensus_branch_id, have_orchard_zsa = True, have_burn = True, have_issuance = True):

        # Since burn is part of the OrchardZSA bundle, ensure that there are no burn fields
        # when there are no OrchardZSA fields
        assert have_orchard_zsa or not have_burn

        # Most of the Common Transaction Fields, and all the Transparent and Sapling Transaction Fields
        # are initialized in the super (TransactionBase) class.
        super().__init__(rand)

        # Common Transaction Fields that are not in TransactionBase
        self.nVersionGroupId = NU7_VERSION_GROUP_ID
        self.nConsensusBranchId = consensus_branch_id

        # Orchard-ZSA Transaction Fields
        self.vActionsOrchardZSA = []
        if have_orchard_zsa:
            for _ in range(rand.u8() % 5):
                self.vActionsOrchardZSA.append(OrchardZSAActionDescription(rand))
            self.flagsOrchardZSA = rand.u8() & 7 # Only three flag bits are currently defined.
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
            for _ in range(rand.u8() % 5):
                self.vIssueActions.append(IssueActionDescription(rand))
            self.ik = rand.b(32)
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
            ret += bytes(self.ik)
            ret += bytes(self.issueAuthSig)
        return ret

    def __bytes__(self):
        ret = b''

        # Common Transaction Fields that are not in TransactionBase
        ret += struct.pack('<I', self.version_bytes())
        ret += struct.pack('<I', self.nVersionGroupId)
        ret += struct.pack('<I', self.nConsensusBranchId)

        # Fields that are in TransactionBase: Common, Transparent, Sapling
        ret += super().__bytes__()

        # OrchardZSA Transaction Fields
        ret += self.orchard_zsa_transfer_field_bytes()

        # OrchardZSA Burn Fields
        ret += self.orchard_zsa_burn_field_bytes()

        # ZSA Issuance Fields
        ret += self.issuance_field_bytes()

        return ret