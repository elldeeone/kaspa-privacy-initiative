import assert from 'node:assert/strict';

function consensusFields(value) {
  if (Array.isArray(value)) return value.map(consensusFields);
  if (value && typeof value === 'object') return Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== 'verboseData')
      .map(([key, entry]) => [key, consensusFields(entry)]));
  return value;
}

export function acceptedExactBundle(chain, intent, envelope, expected) {
  assert.equal(chain.removedChainBlockHashes.length, 0, 'reorg: stop and inspect');
  for (const block of chain.chainBlockAcceptedTransactions) {
    const tx = block.acceptedTransactions.find(t => t.verboseData.transactionId === intent.transactionId);
    if (!tx) continue;
    assert.equal(tx.payload, expected.toString('hex'), 'accepted payload differs');
    assert.deepEqual(consensusFields(tx), consensusFields(envelope.record.transaction),
      'accepted transaction body differs');
    return true;
  }
  return false;
}
