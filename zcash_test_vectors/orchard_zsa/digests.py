#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2b
import struct

from zcash_test_vectors.transaction_zsa import (
    TransactionZSA, IssueActionDescription,
)


def orchard_zsa_burn_digest(tx: TransactionZSA):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcBurnHash')

    if len(tx.vAssetBurnOrchardZSA) > 0:
        for desc in tx.vAssetBurnOrchardZSA:
            digest.update(bytes(desc.assetBase))
            digest.update(struct.pack('<Q', desc.valueBurn))

    return digest.digest()


def issuance_digest(tx: TransactionZSA):
    digest = blake2b(digest_size=32, person=b'ZTxIdSAIssueHash')

    if len(tx.vIssueActions) > 0:
        digest.update(issue_actions_digest(tx))
        digest.update(tx.ik)

    return digest.digest()


def issuance_auth_digest(tx: TransactionZSA):
    digest = blake2b(digest_size=32, person=b'ZTxAuthZSAOrHash')
    if len(tx.vIssueActions) > 0:
        digest.update(tx.issueAuthSig)
    return digest.digest()


def issue_actions_digest(tx: TransactionZSA):
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


def main():
    from zcash_test_vectors.zip_0244 import rand_gen, populate_test_vector, generate_test_vectors
    consensus_branch_id = 0x77777777  # NU7
    rand = rand_gen()
    test_vectors = []

    # Since the burn fields are within the Orchard ZSA fields, we can't have burn without Orchard ZSA.
    # This gives us the following choices for [have_orchard_zsa, have_burn, have_issuance]:
    allowed_choices = [
        [False, False, False],
        [False, False, True],
        [True, False, False],
        [True, False, True],
        [True, True, False],
        [True, True, True]
    ]

    for choice in allowed_choices:
        for _ in range(2):    # We generate two test vectors for each choice.
            tx = TransactionZSA(rand, consensus_branch_id, *choice)
            populate_test_vector(rand, test_vectors, tx)

    generate_test_vectors('orchard_zsa_digests', test_vectors)


if __name__ == '__main__':
    main()
