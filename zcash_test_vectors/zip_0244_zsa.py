#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2b
import struct

from .transaction import (
    MAX_MONEY,
    NU5_TX_VERSION,
    Script,
    TransactionV5,
)
from .transaction_zsa import (
    NU7_TX_VERSION,
    TransactionZSA, IssueActionDescription,
)
from .output import render_args, render_tv, Some
from .rand import Rand
from .zip_0143 import (
    getHashOutputs,
    getHashPrevouts,
    getHashSequence,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
)
from .zip_0244 import (
    transparent_digest, transparent_scripts_digest,
    sapling_digest, sapling_auth_digest,
    header_digest, TransparentInput, transparent_sig_digest,
)

# Orchard

def orchard_zsa_digest(tx: TransactionZSA):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrchardHash')

    if len(tx.vActionsOrchardZSA) > 0:
        digest.update(orchard_zsa_actions_compact_digest(tx))
        digest.update(orchard_zsa_actions_memos_digest(tx))
        digest.update(orchard_zsa_actions_noncompact_digest(tx))
        digest.update(orchard_zsa_burn_digest(tx))
        digest.update(struct.pack('<B', tx.flagsOrchardZSA))
        digest.update(struct.pack('<Q', tx.valueBalanceOrchardZSA))
        digest.update(bytes(tx.anchorOrchardZSA))

    return digest.digest()

def orchard_zsa_auth_digest(tx: TransactionZSA):
    digest = blake2b(digest_size=32, person=b'ZTxAuthOrchaHash')

    if len(tx.vActionsOrchardZSA) > 0:
        digest.update(tx.proofsOrchardZSA)
        for desc in tx.vActionsOrchardZSA:
            digest.update(bytes(desc.spendAuthSig))
        digest.update(bytes(tx.bindingSigOrchardZSA))

    return digest.digest()

# - Actions

def orchard_zsa_actions_compact_digest(tx: TransactionZSA):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcActCHash')
    for desc in tx.vActionsOrchardZSA:
        digest.update(bytes(desc.nullifier))
        digest.update(bytes(desc.cmx))
        digest.update(bytes(desc.ephemeralKey))
        digest.update(desc.encCiphertext[:84])
    return digest.digest()

def orchard_zsa_actions_memos_digest(tx: TransactionZSA):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcActMHash')
    for desc in tx.vActionsOrchardZSA:
        digest.update(desc.encCiphertext[84:596])
    return digest.digest()

def orchard_zsa_actions_noncompact_digest(tx: TransactionZSA):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcActNHash')
    for desc in tx.vActionsOrchardZSA:
        digest.update(bytes(desc.cv))
        digest.update(bytes(desc.rk))
        digest.update(desc.encCiphertext[596:])
        digest.update(desc.outCiphertext)
    return digest.digest()

def orchard_zsa_burn_digest(tx: TransactionZSA):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcBurnHash')

    if len(tx.vAssetBurnOrchardZSA) > 0:
        for desc in tx.vAssetBurnOrchardZSA:
            digest.update(bytes(desc.AssetBase))
            digest.update(struct.pack('<Q', desc.valueBurn))

    return digest.digest()

def issuance_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSAIssueHash')

    if len(tx.vIssueActions) > 0:
        digest.update(issue_actions_digest(tx))
        digest.update(bytes(tx.ik))

    return digest.digest()

def issuance_auth_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxAuthZSAOrHash')
    if len(tx.vIssueActions) > 0:
        digest.update(tx.issueAuthSig)
    return digest.digest()

def issue_actions_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdIssuActHash')

    for action in tx.vIssueActions:
        digest.update(issue_notes_digest(action))
        digest.update(action.asset_desc)
        digest.update(struct.pack('<B', action.flagsIssuance))

    return digest.digest()

def issue_notes_digest(action: IssueActionDescription):
    digest = blake2b(digest_size=32, person=b'ZTxIdIAcNoteHash')

    for note in action.vNotes:
        digest.update(bytes(note.recipient))
        digest.update(struct.pack('<Q', note.value))
        digest.update(bytes(note.assetBase))
        digest.update(bytes(note.rho))
        digest.update(note.rseed)

    return digest.digest()


# Transaction

def txid_digest(tx: TransactionZSA):
    digest = blake2b(
        digest_size=32,
        person=b'ZcashTxHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(header_digest(tx))
    digest.update(transparent_digest(tx))
    digest.update(sapling_digest(tx))
    digest.update(orchard_zsa_digest(tx))
    digest.update(issuance_digest(tx))

    return digest.digest()

# Authorizing Data Commitment

def auth_digest(tx: TransactionZSA):
    digest = blake2b(
        digest_size=32,
        person=b'ZTxAuthHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(transparent_scripts_digest(tx))
    digest.update(sapling_auth_digest(tx))
    digest.update(orchard_zsa_auth_digest(tx))
    digest.update(issuance_auth_digest(tx))

    return digest.digest()

# Signatures

def signature_digest(tx: TransactionZSA, t_inputs, nHashType, txin):
    digest = blake2b(
        digest_size=32,
        person=b'ZcashTxHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(header_digest(tx))
    digest.update(transparent_sig_digest(tx, t_inputs, nHashType, txin))
    digest.update(sapling_digest(tx))
    digest.update(orchard_zsa_digest(tx))
    digest.update(issuance_digest(tx))

    return digest.digest()

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

    consensusBranchId = 0x77777777 # NU7

    test_vectors = []
    allowed_choices = [[False,False,False],[False,False,True],[True,False,False],[True,False,True],[True,True,False],[True,True,True]]
    for choice in allowed_choices:
    # for _ in range(10):
        tx = TransactionZSA(rand, consensusBranchId, choice[0], choice[1], choice[2])
        # tx = TransactionZSA(rand, consensusBranchId, False, False, True)
        txid = txid_digest(tx)
        auth = auth_digest(tx)

        # Generate amounts and scriptCodes for each non-dummy transparent input.
        if tx.is_coinbase():
            t_inputs = []
        else:
            t_inputs = [TransparentInput(nIn, rand) for nIn in range(len(tx.vin))]

        # If there are any non-dummy transparent inputs, derive a corresponding transparent sighash.
        if len(t_inputs) > 0:
            txin = rand.a(t_inputs)
        else:
            txin = None

        sighash_shielded = signature_digest(tx, t_inputs, SIGHASH_ALL, None)
        other_sighashes = {
            nHashType: None if txin is None else signature_digest(tx, t_inputs, nHashType, txin)
            for nHashType in ([
                                  SIGHASH_ALL,
                                  SIGHASH_NONE,
                                  SIGHASH_SINGLE,
                                  SIGHASH_ALL | SIGHASH_ANYONECANPAY,
                                  SIGHASH_NONE | SIGHASH_ANYONECANPAY,
                                  SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
                                  ] if txin is None or txin.nIn < len(tx.vout) else [
                SIGHASH_ALL,
                SIGHASH_NONE,
                SIGHASH_ALL | SIGHASH_ANYONECANPAY,
                SIGHASH_NONE | SIGHASH_ANYONECANPAY,
                ])
        }

        test_vectors.append({
            'tx': bytes(tx),
            'txid': txid,
            'auth_digest': auth,
            'amounts': [x.amount for x in t_inputs],
            'script_pubkeys': [x.scriptPubKey.raw() for x in t_inputs],
            'transparent_input': None if txin is None else txin.nIn,
            'sighash_shielded': sighash_shielded,
            'sighash_all': other_sighashes.get(SIGHASH_ALL),
            'sighash_none': other_sighashes.get(SIGHASH_NONE),
            'sighash_single': other_sighashes.get(SIGHASH_SINGLE),
            'sighash_all_anyone': other_sighashes.get(SIGHASH_ALL | SIGHASH_ANYONECANPAY),
            'sighash_none_anyone': other_sighashes.get(SIGHASH_NONE | SIGHASH_ANYONECANPAY),
            'sighash_single_anyone': other_sighashes.get(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY),
        })

    render_tv(
        args,
        'zip_0244',
        (
            ('tx',                    {'rust_type': 'Vec<u8>', 'bitcoin_flavoured': False}),
            ('txid',                  '[u8; 32]'),
            ('auth_digest',           '[u8; 32]'),
            ('amounts',               'Vec<i64>'),
            ('script_pubkeys',        {'rust_type': 'Vec<Vec<u8>>', 'bitcoin_flavoured': False}),
            ('transparent_input',     'Option<u32>'),
            ('sighash_shielded',      '[u8; 32]'),
            ('sighash_all',           'Option<[u8; 32]>'),
            ('sighash_none',          'Option<[u8; 32]>'),
            ('sighash_single',        'Option<[u8; 32]>'),
            ('sighash_all_anyone',    'Option<[u8; 32]>'),
            ('sighash_none_anyone',   'Option<[u8; 32]>'),
            ('sighash_single_anyone', 'Option<[u8; 32]>'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
