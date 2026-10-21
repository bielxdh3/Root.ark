'use strict';

// Synthetic, process-local feasibility models only. These classes do not
// provide PostgreSQL isolation, durable storage, distributed authority, or
// physical storage/network fencing.

function errorWithCode(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function copy(value) {
  return structuredClone(value);
}

const DEFAULT_SCOPE = Object.freeze({
  accountId: 'synthetic-account',
  compartmentId: 'synthetic-compartment',
  keyringId: 'synthetic-keyring',
});

function scopeKey(scope = DEFAULT_SCOPE) {
  const parts = [scope?.accountId, scope?.compartmentId, scope?.keyringId];
  if (parts.some((part) => typeof part !== 'string' || part.length === 0)) {
    throw errorWithCode('INVALID_SCOPE', 'mock CAS scope requires account, compartment, and keyring identifiers');
  }
  return JSON.stringify(parts);
}

function emptyCasState() {
  return {
    head: { revision: 0, digest: 'genesis' },
    transitions: [],
    operations: [],
    noCommitFences: [],
  };
}

class MockCasLedger {
  constructor() {
    this._states = new Map();
    this._tail = Promise.resolve();
  }

  snapshot(scope = DEFAULT_SCOPE) {
    const key = scopeKey(scope);
    return copy(this._states.get(key) || emptyCasState());
  }

  async _exclusive(action) {
    const previous = this._tail;
    let release;
    this._tail = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      return await action();
    } finally {
      release();
    }
  }

  async commit({ scope = DEFAULT_SCOPE, operationId, expectedRevision, payloadDigest, failAfterTransition = false, loseAcknowledgement = false }) {
    const outcome = await this._exclusive(() => {
      const key = scopeKey(scope);
      const draft = copy(this._states.get(key) || emptyCasState());
      const priorOperation = draft.operations.find((row) => row.operationId === operationId);
      if (priorOperation) {
        if (priorOperation.payloadDigest !== payloadDigest) {
          throw errorWithCode('OPERATION_CONFLICT', 'operation id was already used with a different digest');
        }
        return { result: priorOperation.result, committedNow: false };
      }
      if (draft.noCommitFences.some((row) => row.operationId === operationId)) {
        throw errorWithCode('NO_COMMIT_FENCED', 'operation has a terminal no-commit fence');
      }
      if (draft.head.revision !== expectedRevision) {
        throw errorWithCode('STALE_HEAD', 'expected revision does not match the mock head');
      }

      const result = {
        operationId,
        payloadDigest,
        fromRevision: draft.head.revision,
        toRevision: draft.head.revision + 1,
        transitionIndex: draft.transitions.length,
      };
      draft.transitions.push({ ...result });
      if (failAfterTransition) {
        throw errorWithCode('INJECTED_ROLLBACK', 'injected failure before the mock transaction publishes its draft');
      }
      draft.head = { revision: result.toRevision, digest: payloadDigest };
      draft.operations.push({ operationId, payloadDigest, result: copy(result) });
      this._states.set(key, draft);
      return { result, committedNow: true };
    });

    if (loseAcknowledgement && outcome.committedNow) {
      throw errorWithCode('LOST_ACK', 'mock transaction committed before its caller acknowledgement was lost');
    }
    return copy(outcome.result);
  }

  async sealNoCommit({ scope = DEFAULT_SCOPE, operationId, expectedRevision, payloadDigest, failAfterFence = false }) {
    return this._exclusive(() => {
      const key = scopeKey(scope);
      const draft = copy(this._states.get(key) || emptyCasState());
      const priorFence = draft.noCommitFences.find((row) => row.operationId === operationId);
      if (priorFence) {
        if (priorFence.payloadDigest !== payloadDigest) {
          throw errorWithCode('OPERATION_CONFLICT', 'operation id was already fenced with a different digest');
        }
        return copy(priorFence);
      }
      if (draft.operations.some((row) => row.operationId === operationId)) {
        throw errorWithCode('ALREADY_COMMITTED', 'committed operation cannot be marked no-commit');
      }
      if (draft.head.revision !== expectedRevision) {
        throw errorWithCode('STALE_HEAD', 'expected revision does not match the mock head');
      }

      const fence = {
        operationId,
        payloadDigest,
        headRevision: draft.head.revision,
        fenceIndex: draft.noCommitFences.length,
      };
      draft.noCommitFences.push(fence);
      if (failAfterFence) {
        throw errorWithCode('INJECTED_ROLLBACK', 'injected failure before the mock fence publishes its draft');
      }
      this._states.set(key, draft);
      return copy(fence);
    });
  }
}

class MockGateAuthority {
  constructor() {
    this._mode = 'OPEN';
    this._generation = 1;
    this._nextPermit = 1;
    this._nextLease = 1;
    this._permits = [];
    this._effects = [];
    this._stopRequests = [];
    this._noCommitFence = null;
  }

  snapshot() {
    return copy({
      mode: this._mode,
      generation: this._generation,
      permits: this._permits,
      effects: this._effects,
      stopRequests: this._stopRequests,
      noCommitFence: this._noCommitFence,
    });
  }

  _requireOpen() {
    if (this._mode !== 'OPEN') {
      throw errorWithCode('GATE_NOT_OPEN', 'mock gate does not authorize new effects');
    }
  }

  issuePermit({ operationId, effectId }) {
    this._requireOpen();
    const permit = {
      permitId: `permit-${this._nextPermit++}`,
      operationId,
      effectId,
      generation: this._generation,
      state: 'UNUSED',
    };
    this._permits.push(permit);
    return copy(permit);
  }

  consumePermit({ permitId, operationId, effectId }) {
    this._requireOpen();
    const permit = this._permits.find((row) => row.permitId === permitId);
    if (!permit) throw errorWithCode('UNKNOWN_PERMIT', 'permit is not present in this mock authority');
    if (permit.operationId !== operationId || permit.effectId !== effectId) {
      throw errorWithCode('SCOPE_MISMATCH', 'permit is bound to another operation or effect');
    }
    if (permit.generation !== this._generation) {
      throw errorWithCode('STALE_GENERATION', 'permit belongs to an older mock gate generation');
    }
    if (permit.state !== 'UNUSED') {
      throw errorWithCode('PERMIT_ALREADY_CONSUMED', 'permit can be consumed only once');
    }

    permit.state = 'CONSUMED';
    const effect = {
      leaseId: `lease-${this._nextLease++}`,
      operationId,
      effectId,
      permitId,
      generation: this._generation,
      state: 'ACTIVE',
      chunks: [],
      stopAcknowledgementId: null,
    };
    this._effects.push(effect);
    return copy({ leaseId: effect.leaseId, generation: effect.generation });
  }

  performChunk({ leaseId, chunkIndex }) {
    this._requireOpen();
    const effect = this._effects.find((row) => row.leaseId === leaseId);
    if (!effect) throw errorWithCode('UNKNOWN_EFFECT', 'effect lease is not present in this mock authority');
    if (effect.state !== 'ACTIVE' || effect.generation !== this._generation) {
      throw errorWithCode('EFFECT_NOT_ACTIVE', 'effect lease is no longer active in the current generation');
    }
    if (chunkIndex !== effect.chunks.length) {
      throw errorWithCode('CHUNK_ORDER', 'mock chunks must pass through the gate in sequence');
    }

    // This only appends to an in-memory journal; it does not perform real I/O.
    effect.chunks.push({ chunkIndex, generation: this._generation });
  }

  quiesce() {
    this._requireOpen();
    this._mode = 'QUIESCING';
    this._generation += 1;
    this._stopRequests = this._effects
      .filter((effect) => effect.state === 'ACTIVE')
      .map((effect) => ({
        effectId: effect.effectId,
        leaseId: effect.leaseId,
        acknowledgementId: `stop-${effect.leaseId}-g${this._generation}`,
      }));
    return copy({ generation: this._generation, stopRequests: this._stopRequests });
  }

  acknowledgeStop({ effectId, acknowledgementId }) {
    if (this._mode !== 'QUIESCING') {
      throw errorWithCode('GATE_NOT_QUIESCING', 'stop acknowledgements are accepted only while quiescing');
    }
    const request = this._stopRequests.find((row) => row.effectId === effectId);
    if (!request || request.acknowledgementId !== acknowledgementId) {
      throw errorWithCode('INVALID_STOP_ACK', 'stop acknowledgement does not match the mock request');
    }
    const effect = this._effects.find((row) => row.leaseId === request.leaseId);
    if (effect.state === 'STOPPED') {
      throw errorWithCode('STOP_ALREADY_ACKNOWLEDGED', 'effect already has a mock stop acknowledgement');
    }
    effect.state = 'STOPPED';
    effect.stopAcknowledgementId = acknowledgementId;
  }

  sealNoCommit(operationId) {
    if (this._mode !== 'QUIESCING') {
      throw errorWithCode('GATE_NOT_QUIESCING', 'mock no-commit seal requires a quiescing gate');
    }
    if (this._effects.some((effect) => effect.state !== 'STOPPED')) {
      throw errorWithCode('STOP_ACK_REQUIRED', 'every active mock effect needs an explicit stop acknowledgement');
    }
    this._noCommitFence = { operationId, generation: this._generation };
    this._mode = 'BLOCKED';
    return copy(this._noCommitFence);
  }
}

module.exports = { MockCasLedger, MockGateAuthority };
