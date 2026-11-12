'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const vm = require('node:vm');

const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const start = server.indexOf('  const authorizeP2pObject = async (');
const end = server.indexOf('\n  const p2pBroker = makeBroker(', start);
assert.ok(start !== -1 && end > start, 'extract exact active object authorization closure');

test('issue 242 P2: non-owner and missing explicit grants are denied before hashing ciphertext', async () => {
  let digests = 0;
  const metadata = { fileName: 'sealed.bin', folderId: 'root',
    uploadedAt: '2026-11-06T12:00:00Z', size: 64, encryptedSize: 92,
    encryptionLevel: 'user-key', algorithm: 'aes-256-gcm',
    layers: [{ type: 'user' }],
    accessControl: { owner: 'alice', authorizedUsers: ['alice', 'bob'], expiresAt: null } };
  const fileAcl = { public: false, owner: 'alice', users: { bob: { read: true } } };
  const context = {
    path, crypto, Date,
    isCloudStorageEnabled: () => false,
    getEncryptedFileKey: () => 'root/sealed.bin',
    loadEncryptedFiles: () => ({ 'root/sealed.bin': metadata }),
    currentP2pCiphertext: async () => {
      digests++;
      return { bytes: 92, sha256: 'b'.repeat(64) };
    },
    p2pUser: username => ({ username, disabled: false, permissions: { listFiles: true } }),
    normalizeUserPermissions: user => user.permissions,
    getFolderById: () => ({ id: 'root' }),
    isFolderAvailable: () => true,
    isFileExpired: () => false,
    isFileInTrash: () => false,
    isStoredVersionFile: () => false,
    restoreProviderOrphans: { isSuppressed: () => false },
    getFilePermissionEntry: () => fileAcl,
    loadFilePermissions: () => ({ 'root/sealed.bin': fileAcl }),
    normalizeFilePermissionEntry: value => value,
    hasFolderAccess: () => true,
    hasFileAccess: () => true,
  };
  const authorize = vm.runInNewContext(server.slice(start, end) + '\nauthorizeP2pObject', context);
  const boundObject = { folderId: 'root', fileName: 'sealed.bin' };

  assert.equal(await authorize({ owner: 'bob', recipient: null, boundObject, pin: null }), null);
  assert.equal(digests, 0, 'non-owner may not trigger even the first ciphertext read/hash');
  fileAcl.users = {};
  assert.equal(await authorize({ owner: 'alice', recipient: 'bob', boundObject, pin: null }), null);
  assert.equal(digests, 0, 'recipient without explicit ACL may not hash ciphertext');

  fileAcl.users.bob = { read: true };
  const allowed = await authorize({ owner: 'alice', recipient: 'bob', boundObject, pin: null });
  assert.ok(allowed && /^[a-f0-9]{64}$/.test(allowed.fingerprint), 'valid owner/recipient grants retain a real fingerprint');
  assert.equal(digests, 1, 'positive control actually executes the expensive ciphertext hash');
});
