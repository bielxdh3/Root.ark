"use strict";

// MOCK-ONLY contract model. It uses shared in-memory objects and branded JS values;
// it provides no cryptographic, persistence, linearizability, crash-safety, or deployment evidence.

const crypto = require("node:crypto");

const tickets = new WeakMap();
const statusReceipts = new WeakMap();

function modelError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function isBytes(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array;
}

function copyBytes(value, length) {
  if (!isBytes(value) || (length !== undefined && value.byteLength !== length)) throw modelError("INVALID_REQUEST");
  return Buffer.from(value);
}

function sameBytes(left, right) {
  return isBytes(left) && isBytes(right) && left.byteLength === right.byteLength
    && crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right));
}

function cloneScope(scope) {
  return {
    accountId: copyBytes(scope?.accountId, 16),
    compartmentId: copyBytes(scope?.compartmentId),
    keyringId: copyBytes(scope?.keyringId, 16),
  };
}

function sameScope(left, right) {
  return sameBytes(left?.accountId, right?.accountId)
    && sameBytes(left?.compartmentId, right?.compartmentId)
    && sameBytes(left?.keyringId, right?.keyringId);
}

function stable(value) {
  if (isBytes(value)) return `bytes:${Buffer.from(value).toString("hex")}`;
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function cloneHead(head) {
  return {
    revision: head.revision,
    epoch: head.epoch,
    activeDeviceIds: [...head.activeDeviceIds],
    recoveryPackageId: head.recoveryPackageId,
  };
}

function exactSequence(values, expected) {
  return Array.isArray(values) && values.length === expected.length
    && expected.every((value, index) => values[index] === value);
}

class FakeCasStore {
  constructor(initialHead) {
    this.head = cloneHead(initialHead);
    this.operations = new Map();
    this.reservations = new Map();
    this.noCommitTombstones = new Map();
  }
}

class FakeWitness {
  constructor(initialHead) {
    this.head = cloneHead(initialHead);
    this.pending = null;
    this.available = true;
    this.freshHeadReadRevision = null;
  }
}

class FakeCasStatusAuthority {
  constructor(casStore, durableState) {
    this.casStore = casStore;
    this.durableState = durableState;
    this.available = true;
    this.sequence = 0;
  }

  issueTerminalStatusReceipt(record) {
    if (!this.available) throw modelError("STATUS_AUTHORITY_UNAVAILABLE");
    const committed = this.casStore.operations.get(record.operationIdHex);
    let status;
    let headRevision;
    if (committed) {
      if (committed.reservationId !== record.reservationId
        || committed.requestDigest !== record.requestDigest
        || this.casStore.head.revision !== record.nextHead.revision) throw modelError("RESERVATION_UNRESOLVED");
      status = "committed";
      headRevision = record.nextHead.revision;
    } else {
      const tombstone = this.casStore.noCommitTombstones.get(record.operationIdHex);
      if (this.durableState.now < record.expiresAt + 30
        || this.casStore.head.revision !== record.baseRevision
        || this.casStore.operations.has(record.operationIdHex)
        || (tombstone !== undefined && tombstone !== record.requestDigest)) throw modelError("RESERVATION_UNRESOLVED");
      if (tombstone === undefined) this.casStore.noCommitTombstones.set(record.operationIdHex, record.requestDigest);
      status = "not-committed";
      headRevision = record.baseRevision;
    }
    this.sequence += 1;
    const receipt = {
      type: "MOCK_ONLY_FAKE_CAS_STATUS",
      status,
      reservationId: record.reservationId,
      operationId: Buffer.from(record.operationId),
      scope: cloneScope(record.scope),
      baseRevision: record.baseRevision,
      headRevision,
      requestDigest: Buffer.from(record.requestDigest, "hex"),
      nonce: Buffer.alloc(16, this.sequence & 0xff),
    };
    statusReceipts.set(receipt, {
      durableState: this.durableState,
      reservationId: record.reservationId,
      status,
      snapshot: stable(receipt),
    });
    return receipt;
  }
}

class FakeContentAdmissionGate {
  constructor(model) {
    this.model = model;
  }

  admit(input) {
    const { durableState, casStore, witness } = this.model;
    if (!witness.available) throw modelError("WITNESS_UNAVAILABLE");
    if (witness.pending) throw modelError("PENDING_RESERVATION");
    if (witness.head.revision !== casStore.head.revision
      || witness.head.epoch !== casStore.head.epoch) throw modelError("ROLLBACK_RESISTANCE_INCOMPLETE");
    if (this.model.applicationRevision !== witness.head.revision
      || input.revision !== witness.head.revision) throw modelError("STALE_HEAD");
    if (!witness.head.activeDeviceIds.includes(input.actorId)) throw modelError("UNAUTHORIZED_ACTOR");
    if (durableState.pendingReservationId) throw modelError("PENDING_RESERVATION");
    return true;
  }
}

class FakeRecoveryStateModel {
  constructor(options) {
    if (options?._durableState) {
      this.durableState = options._durableState;
      this.scope = cloneScope(this.durableState.scope);
      this.casStore = this.durableState.casStore;
      this.witness = this.durableState.witness;
      this.statusAuthority = this.durableState.statusAuthority;
      this.applicationRevision = options.restoreApplicationRevision ?? this.durableState.casStore.head.revision;
    } else {
      this.scope = cloneScope(options?.scope);
      const initialHead = {
        revision: options.initialRevision,
        epoch: options.initialEpoch,
        activeDeviceIds: [...options.activeDeviceIds],
        recoveryPackageId: options.recoveryPackageId ?? null,
      };
      this.casStore = new FakeCasStore(initialHead);
      this.witness = new FakeWitness(initialHead);
      this.durableState = {
        scope: this.scope,
        casStore: this.casStore,
        witness: this.witness,
        statusAuthority: null,
        now: options.now,
        pendingReservationId: null,
        nextReservation: 0,
        localEpoch: initialHead.epoch,
        localRecoveryPackageId: initialHead.recoveryPackageId,
      };
      this.statusAuthority = new FakeCasStatusAuthority(this.casStore, this.durableState);
      this.durableState.statusAuthority = this.statusAuthority;
      this.applicationRevision = initialHead.revision;
    }
    this.admissionGate = new FakeContentAdmissionGate(this);
  }

  get pendingReservationId() {
    return this.witness.pending?.reservationId ?? null;
  }

  get localEpoch() {
    return this.durableState.localEpoch;
  }

  get localRecoveryPackageId() {
    return this.durableState.localRecoveryPackageId;
  }

  get freshHeadReadRevision() {
    return this.witness.freshHeadReadRevision;
  }

  reserveTransition(request) {
    const scope = cloneScope(request?.scope);
    if (!sameScope(scope, this.scope)) throw modelError("SCOPE_MISMATCH");
    const operationId = copyBytes(request.operationId, 16);
    const operationIdHex = operationId.toString("hex");
    const requestBytes = copyBytes(request.requestBytes);
    const requestDigest = crypto.createHash("sha256").update(requestBytes).digest("hex");
    const existing = this.casStore.reservations.get(operationIdHex);
    if (existing) {
      if (existing.requestDigest !== requestDigest || !sameScope(existing.scope, scope)) {
        throw modelError("IDEMPOTENCY_CONFLICT");
      }
      return existing.ticket;
    }
    if (this.witness.pending) throw modelError("PENDING_RESERVATION");
    if (this.witness.available !== true) throw modelError("WITNESS_UNAVAILABLE");
    if (this.casStore.head.revision !== this.witness.head.revision
      || this.applicationRevision !== this.witness.head.revision
      || request.expectedRevision !== this.witness.head.revision) throw modelError("CAS_CONFLICT");
    if (!this.witness.head.activeDeviceIds.includes(request.actorId)) throw modelError("UNAUTHORIZED_ACTOR");
    if (!Number.isSafeInteger(request.issuedAt) || !Number.isSafeInteger(request.expiresAt)
      || request.expiresAt <= request.issuedAt || request.expiresAt - request.issuedAt > 300
      || this.durableState.now < request.issuedAt - 30 || this.durableState.now > request.expiresAt) {
      throw modelError("AUTHORIZATION_EXPIRED");
    }

    const currentHead = cloneHead(this.casStore.head);
    const nextHead = this.#deriveNextHead(request, currentHead);
    this.durableState.nextReservation += 1;
    const reservationId = `fake-reservation-${this.durableState.nextReservation}`;
    const ticket = Object.freeze({
      reservationId,
      operationId: Buffer.from(operationId),
      scope: cloneScope(scope),
      baseRevision: currentHead.revision,
      nextRevision: nextHead.revision,
    });
    tickets.set(ticket, {
      durableState: this.durableState,
      reservationId,
      operationIdHex,
      operationId: Buffer.from(operationId),
    });
    const record = {
      reservationId,
      operationId: Buffer.from(operationId),
      operationIdHex,
      requestDigest,
      requestBytes,
      scope,
      baseRevision: currentHead.revision,
      expiresAt: request.expiresAt,
      nextHead,
      ticket,
      state: "pending",
      casResult: null,
    };
    this.casStore.reservations.set(operationIdHex, record);
    this.witness.pending = record;
    this.durableState.pendingReservationId = reservationId;
    // The pending witness gate is installed before this method returns its ticket.
    return ticket;
  }

  #deriveNextHead(request, currentHead) {
    const active = currentHead.activeDeviceIds;
    if (request.operationType === "revoke-device") {
      if (typeof request.targetDeviceId !== "string" || !active.includes(request.targetDeviceId)) {
        throw modelError("UNAUTHORIZED_ACTOR");
      }
      const remaining = active.filter((deviceId) => deviceId !== request.targetDeviceId);
      if (remaining.length === 0 && !currentHead.recoveryPackageId) {
        throw modelError("COMPROMISE_RECOVERY_UNAVAILABLE");
      }
      return {
        ...currentHead,
        revision: currentHead.revision + 1,
        epoch: currentHead.epoch + 1,
        activeDeviceIds: remaining,
      };
    }
    if (request.operationType === "compromise-package") {
      if (!currentHead.recoveryPackageId || request.compromisedPackageId !== currentHead.recoveryPackageId
        || typeof request.replacementPackageId !== "string" || !request.replacementPackageId
        || request.replacementPackageId === currentHead.recoveryPackageId
        || active.length === 0) throw modelError("COMPROMISE_RECOVERY_UNAVAILABLE");
      const oldEpochs = Array.from({ length: currentHead.epoch }, (_, index) => index + 1);
      const nextEpoch = currentHead.epoch + 1;
      if (!exactSequence(request.priorEpochsAvailable, oldEpochs)) throw modelError("KEY_COVERAGE_INCOMPLETE");
      const expectedWrapEpochs = [...oldEpochs, nextEpoch];
      if (request.recoveryWrapPackageId !== request.replacementPackageId
        || !exactSequence(request.recoveryWrapEpochs, expectedWrapEpochs)) throw modelError("KEY_COVERAGE_INCOMPLETE");
      if (request.deviceWrapRecipients?.length !== active.length
        || active.some((deviceId, index) => request.deviceWrapRecipients[index] !== deviceId)) {
        throw modelError("KEY_COVERAGE_INCOMPLETE");
      }
      if (typeof request.newEpochKeyId !== "string" || !request.newEpochKeyId) {
        throw modelError("COMPROMISE_RECOVERY_UNAVAILABLE");
      }
      return {
        ...currentHead,
        revision: currentHead.revision + 1,
        epoch: nextEpoch,
        recoveryPackageId: request.replacementPackageId,
      };
    }
    throw modelError("UNKNOWN_RECOVERY_OPERATION");
  }

  #recordForTicket(ticket) {
    const identity = ticket && tickets.get(ticket);
    if (!identity || identity.durableState !== this.durableState
      || identity.reservationId !== ticket.reservationId
      || identity.operationIdHex !== Buffer.from(ticket.operationId).toString("hex")
      || !sameBytes(identity.operationId, ticket.operationId)) throw modelError("INVALID_RESERVATION");
    const record = this.casStore.reservations.get(identity.operationIdHex);
    if (!record || record.reservationId !== identity.reservationId) throw modelError("INVALID_RESERVATION");
    return record;
  }

  commitCas(ticket) {
    const record = this.#recordForTicket(ticket);
    if (record.casResult) return cloneHead(record.casResult);
    if (this.casStore.noCommitTombstones.has(record.operationIdHex)) throw modelError("IDEMPOTENCY_CONFLICT");
    if (this.witness.pending !== record || this.casStore.head.revision !== record.baseRevision) throw modelError("CAS_CONFLICT");
    if (this.durableState.now > record.expiresAt) throw modelError("AUTHORIZATION_EXPIRED");
    this.casStore.head = cloneHead(record.nextHead);
    record.casResult = cloneHead(record.nextHead);
    record.state = "cas-committed-unwitnessed";
    this.casStore.operations.set(record.operationIdHex, {
      reservationId: record.reservationId,
      requestDigest: record.requestDigest,
      result: cloneHead(record.nextHead),
    });
    return cloneHead(this.casStore.head);
  }

  issueTerminalStatusReceipt(ticket) {
    const record = this.#recordForTicket(ticket);
    return this.statusAuthority.issueTerminalStatusReceipt(record);
  }

  resumeReservation(reservationId) {
    if (typeof reservationId !== "string" || !reservationId) throw modelError("INVALID_RESERVATION");
    for (const record of this.casStore.reservations.values()) {
      if (record.reservationId === reservationId) return record.ticket;
    }
    throw modelError("INVALID_RESERVATION");
  }

  resolveReservation(ticket, receipt) {
    const record = this.#recordForTicket(ticket);
    const identity = receipt && statusReceipts.get(receipt);
    if (!identity || identity.durableState !== this.durableState
      || identity.reservationId !== record.reservationId
      || identity.snapshot !== stable(receipt)) throw modelError("INVALID_STATUS_PROOF");
    if (!this.witness.available) throw modelError("WITNESS_UNAVAILABLE");
    if (this.witness.pending !== record || this.durableState.pendingReservationId !== record.reservationId) {
      throw modelError("INVALID_STATUS_PROOF");
    }

    if (identity.status === "committed") {
      const operation = this.casStore.operations.get(record.operationIdHex);
      if (!operation || !record.casResult || operation.reservationId !== record.reservationId
        || operation.requestDigest !== record.requestDigest
        || this.casStore.head.revision !== record.nextHead.revision
        || receipt.baseRevision !== record.baseRevision
        || receipt.headRevision !== record.nextHead.revision
        || !sameBytes(receipt.requestDigest, Buffer.from(record.requestDigest, "hex"))) {
        throw modelError("INVALID_STATUS_PROOF");
      }
      this.witness.head = cloneHead(record.nextHead);
      record.state = "committed";
    } else if (identity.status === "not-committed") {
      if (this.durableState.now < record.expiresAt + 30
        || this.casStore.operations.has(record.operationIdHex)
        || this.casStore.head.revision !== record.baseRevision
        || this.casStore.noCommitTombstones.get(record.operationIdHex) !== record.requestDigest
        || receipt.baseRevision !== record.baseRevision
        || receipt.headRevision !== record.baseRevision
        || !sameBytes(receipt.requestDigest, Buffer.from(record.requestDigest, "hex"))) {
        throw modelError("INVALID_STATUS_PROOF");
      }
      // The fake status authority must also demonstrate a fresh committed-head read at r.
      if (this.witness.head.revision !== this.casStore.head.revision) throw modelError("INVALID_STATUS_PROOF");
      this.witness.freshHeadReadRevision = this.casStore.head.revision;
      this.witness.head = cloneHead(this.casStore.head);
      record.state = "cancelled";
    } else {
      throw modelError("INVALID_STATUS_PROOF");
    }

    this.witness.pending = null;
    this.durableState.pendingReservationId = null;
    this.applicationRevision = this.witness.head.revision;
    return record.state;
  }

  admitRead(input) {
    return this.admissionGate.admit(input);
  }

  admitWrite(input) {
    return this.admissionGate.admit(input);
  }

  promoteLocalAfterWitnessedCommit(ticket) {
    const record = this.#recordForTicket(ticket);
    if (!this.witness.available) throw modelError("WITNESS_UNAVAILABLE");
    if (record.state !== "committed" || this.witness.pending
      || this.witness.head.revision !== record.nextHead.revision
      || this.casStore.head.revision !== record.nextHead.revision) throw modelError("COMMITTED_UNWITNESSED");
    this.durableState.localEpoch = record.nextHead.epoch;
    this.durableState.localRecoveryPackageId = record.nextHead.recoveryPackageId;
    return true;
  }

  restart(options = {}) {
    if (options.witnessAvailable !== undefined) this.witness.available = options.witnessAvailable;
    if (options.statusAuthorityAvailable !== undefined) this.statusAuthority.available = options.statusAuthorityAvailable;
    return new FakeRecoveryStateModel({
      _durableState: this.durableState,
      restoreApplicationRevision: options.restoreApplicationRevision ?? this.applicationRevision,
    });
  }

  setWitnessAvailable(available) {
    this.witness.available = available === true;
  }

  setStatusAuthorityAvailable(available) {
    this.statusAuthority.available = available === true;
  }

  advanceClock(now) {
    if (!Number.isSafeInteger(now) || now < this.durableState.now) throw modelError("INVALID_CLOCK");
    this.durableState.now = now;
  }
}

module.exports = {
  FakeCasStatusAuthority,
  FakeCasStore,
  FakeContentAdmissionGate,
  FakeRecoveryStateModel,
  FakeWitness,
};
