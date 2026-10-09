import React, { useState } from 'react';
import {
  Users,
  UserPlus,
  KeyRound,
  ShieldCheck,
  CheckCircle2,
  Lock,
  Copy,
  Check,
  X,
  RefreshCw,
} from 'lucide-react';
import {
  PageShell,
  PageHeader,
  Section,
  PrimaryButton,
  SecondaryButton,
  StatusBadge,
  KeyValueRow,
  HashDisplay,
  TechnicalDetails,
} from './ui/designSystem';
import { Recipient } from '../types';
import { generateRecipientPqcKeys, bytesToHex } from '../crypto/pqc';
import { airGappedLedger } from '../ledger/dlt';
import { airGappedStorage } from '../storage/airGappedStorage';
import { createUnifiedEncryptedKeystore, sanitizeRecipientForPersistence } from '../crypto/keystore';

interface RecipientsViewProps {
  recipients: Recipient[];
  onRecipientAdded?: (newRecipient: Recipient) => void;
}

export const RecipientsView: React.FC<RecipientsViewProps> = ({
  recipients,
  onRecipientAdded,
}) => {
  const [selectedRecipientId, setSelectedRecipientId] = useState<string>(recipients[0]?.id || '');
  const [showAddModal, setShowAddModal] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);

  // New recipient form state
  const [newName, setNewName] = useState('');
  const [newRole, setNewRole] = useState('');
  const [newOrg, setNewOrg] = useState('');
  const [newClearance, setNewClearance] = useState<'TOP SECRET // SCI' | 'SECRET' | 'CONFIDENTIAL'>('SECRET');
  const [newPassphrase, setNewPassphrase] = useState('');

  const selectedRecipient = recipients.find((r) => r.id === selectedRecipientId) || recipients[0];

  const handleEnrollSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim() || !newRole.trim() || newPassphrase.length < 8) return;

    setIsGenerating(true);
    try {
      // Generate genuine NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) keypair
      const keys = await generateRecipientPqcKeys();
      const recipientId = `USR-${Date.now().toString(36).toUpperCase()}`;

      // Encrypt private keys into keystore with user passphrase
      const keystoreRecord = await createUnifiedEncryptedKeystore(
        recipientId,
        keys.fingerprint,
        keys.kemSecretKey,
        keys.dsaSecretKey,
        newPassphrase
      );
      await airGappedStorage.saveKeystore(keystoreRecord);

      const initials = newName
        .split(' ')
        .map((p) => p[0])
        .join('')
        .slice(0, 2)
        .toUpperCase();

      // In-memory recipient object with active keys
      const newRecipient: Recipient = {
        id: recipientId,
        name: newName,
        role: newRole,
        organization: newOrg || 'Directorate of Intelligence',
        clearanceLevel: newClearance,
        avatarInitials: initials,
        isUnlocked: true,
        keys: {
          kemAlgorithm: 'ML-KEM-768',
          kemPublicKeyHex: bytesToHex(keys.kemPublicKey),
          kemSecretKeyHex: bytesToHex(keys.kemSecretKey),
          dsaAlgorithm: 'ML-DSA-65',
          dsaPublicKeyHex: bytesToHex(keys.dsaPublicKey),
          dsaSecretKeyHex: bytesToHex(keys.dsaSecretKey),
          encryptedKeystore: keystoreRecord,
          keyFingerprint: keys.fingerprint,
          registeredAt: Date.now(),
        },
      };

      airGappedLedger.registerRecipient(newRecipient);

      // Persist ONLY sanitized record (no plaintext private keys in storage)
      const sanitizedNew = sanitizeRecipientForPersistence(newRecipient, keystoreRecord);
      const sanitizedExisting = recipients.map((r) =>
        r.keys.encryptedKeystore ? sanitizeRecipientForPersistence(r, r.keys.encryptedKeystore) : r
      );
      await airGappedStorage.saveRecipients([...sanitizedExisting, sanitizedNew]);

      if (onRecipientAdded) {
        onRecipientAdded(newRecipient);
      }

      setSelectedRecipientId(newRecipient.id);
      setShowAddModal(false);
      setNewName('');
      setNewRole('');
      setNewOrg('');
      setNewPassphrase('');
    } catch (err) {
      console.error('Enrollment error:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <PageShell>
      <PageHeader
        title="Recipients"
        description="Manage authorized recipients and local cryptographic identities."
        action={
          <PrimaryButton
            size="sm"
            icon={<UserPlus className="w-3.5 h-3.5" />}
            onClick={() => setShowAddModal(true)}
          >
            Add recipient
          </PrimaryButton>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: Recipient Roster */}
        <div className="lg:col-span-5 space-y-4">
          <Section title="Authorized personnel" description={`${recipients.length} recipients enrolled in local enclave.`}>
            <div className="space-y-2 mt-2">
              {recipients.map((recip) => {
                const isSelected = recip.id === selectedRecipientId;

                return (
                  <div
                    key={recip.id}
                    onClick={() => setSelectedRecipientId(recip.id)}
                    className={`p-3 rounded-lg border transition-all cursor-pointer select-none flex items-center justify-between gap-3 ${
                      isSelected
                        ? 'border-indigo-500 bg-indigo-50/40 text-slate-900 shadow-2xs ring-1 ring-indigo-200'
                        : 'border-slate-200/80 bg-white text-slate-700 hover:border-slate-300 hover:bg-slate-50/60'
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="w-8 h-8 rounded-full bg-slate-100 border border-slate-200 flex items-center justify-center text-xs font-semibold text-slate-700 shrink-0">
                        {recip.avatarInitials}
                      </div>
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-slate-900 truncate">
                          {recip.name}
                        </div>
                        <div className="text-[11px] text-slate-500 truncate">
                          {recip.role}
                        </div>
                      </div>
                    </div>

                    <div className="shrink-0 text-right">
                      <span className="text-[10px] font-mono text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200 font-medium">
                        Active
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </Section>
        </div>

        {/* Right: Selected Identity Detail */}
        <div className="lg:col-span-7 space-y-6">
          {selectedRecipient ? (
            <Section
              title={selectedRecipient.name}
              description={selectedRecipient.role}
              action={
                <StatusBadge status="verified" icon={<CheckCircle2 className="w-3 h-3 text-emerald-600" />}>
                  Identity verified
                </StatusBadge>
              }
            >
              <div className="space-y-4 pt-1">
                {/* Cryptographic Key Registration Status */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="p-3 bg-slate-50 rounded-lg border border-slate-200/80 space-y-1">
                    <span className="text-[11px] text-slate-500 font-medium block">
                      Key exchange
                    </span>
                    <div className="font-semibold text-xs text-slate-900">
                      {selectedRecipient.keys.kemAlgorithm}
                    </div>
                    <span className="text-[10px] text-slate-500 block">
                      Public key registered
                    </span>
                  </div>

                  <div className="p-3 bg-slate-50 rounded-lg border border-slate-200/80 space-y-1">
                    <span className="text-[11px] text-slate-500 font-medium block">
                      Digital signature
                    </span>
                    <div className="font-semibold text-xs text-slate-900">
                      {selectedRecipient.keys.dsaAlgorithm}
                    </div>
                    <span className="text-[10px] text-slate-500 block">
                      Public key registered
                    </span>
                  </div>
                </div>

                {/* Identity Metadata summary */}
                <div className="p-3 bg-slate-50/70 rounded-lg border border-slate-200/80 space-y-2 text-xs">
                  <div className="flex justify-between text-slate-600">
                    <span>Organization:</span>
                    <span className="font-medium text-slate-900">{selectedRecipient.organization}</span>
                  </div>
                  <div className="flex justify-between text-slate-600">
                    <span>Clearance level:</span>
                    <span className="font-medium text-slate-900">{selectedRecipient.clearanceLevel}</span>
                  </div>
                  <div className="flex justify-between text-slate-600">
                    <span>Private key status:</span>
                    <span className="font-medium text-emerald-700">Protected in local keystore</span>
                  </div>
                  <div className="flex justify-between text-slate-600">
                    <span>Key fingerprint:</span>
                    <span className="font-mono text-slate-800">{selectedRecipient.keys.keyFingerprint}</span>
                  </div>
                </div>

                {/* Progressive disclosure of public keys */}
                <TechnicalDetails title="View cryptographic parameters &amp; public key credentials">
                  <KeyValueRow label="Recipient UUID" value={selectedRecipient.id} />
                  <KeyValueRow label="Key Fingerprint" value={selectedRecipient.keys.keyFingerprint} copyable />
                  <KeyValueRow label="ML-KEM-768 Public Key" value={selectedRecipient.keys.kemPublicKeyHex} copyable />
                  <KeyValueRow label="ML-DSA-65 Public Key" value={selectedRecipient.keys.dsaPublicKeyHex} copyable />
                  <div className="pt-2 text-[11px] text-slate-500">
                    Private signing and decapsulation material is protected in the local security environment and never exposed in list views.
                  </div>
                </TechnicalDetails>
              </div>
            </Section>
          ) : null}
        </div>
      </div>

      {/* Add Recipient Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs">
          <div className="max-w-md w-full bg-white rounded-xl shadow-xl border border-slate-200 p-6 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-100">
              <h3 className="text-sm font-semibold text-slate-900">Enroll new recipient</h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="p-1 text-slate-400 hover:text-slate-700 rounded cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleEnrollSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-700 font-medium mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="e.g. Dr. Sarah Connor"
                  className="w-full px-3 py-2 border border-slate-200 rounded-lg text-xs focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                />
              </div>

              <div>
                <label className="block text-slate-700 font-medium mb-1">Role Title</label>
                <input
                  type="text"
                  required
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  placeholder="e.g. Senior Cryptanalyst"
                  className="w-full px-3 py-2 border border-slate-200 rounded-lg text-xs focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                />
              </div>

              <div>
                <label className="block text-slate-700 font-medium mb-1">Organization</label>
                <input
                  type="text"
                  value={newOrg}
                  onChange={(e) => setNewOrg(e.target.value)}
                  placeholder="e.g. Defense Intelligence Agency"
                  className="w-full px-3 py-2 border border-slate-200 rounded-lg text-xs focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                />
              </div>

              <div>
                <label className="block text-slate-700 font-medium mb-1">Clearance Level</label>
                <select
                  value={newClearance}
                  onChange={(e: any) => setNewClearance(e.target.value)}
                  className="w-full px-3 py-2 border border-slate-200 rounded-lg text-xs bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                >
                  <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                  <option value="SECRET">SECRET</option>
                  <option value="TOP SECRET // SCI">TOP SECRET // SCI</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-700 font-medium mb-1">Passphrase (min 8 chars)</label>
                <input
                  type="password"
                  value={newPassphrase}
                  onChange={(e) => setNewPassphrase(e.target.value)}
                  placeholder="Secret passphrase to protect private keys"
                  required
                  minLength={8}
                  className="w-full px-3 py-2 border border-slate-200 rounded-lg text-xs focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                />
              </div>

              <div className="p-3 rounded-lg bg-indigo-50/70 border border-indigo-100 text-[11px] text-indigo-900">
                Generating will create NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) keypairs encrypted at rest with PBKDF2 + AES-256-GCM. Plaintext private keys are never stored in persistence.
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <SecondaryButton size="sm" type="button" onClick={() => setShowAddModal(false)}>
                  Cancel
                </SecondaryButton>
                <PrimaryButton size="sm" type="submit" loading={isGenerating}>
                  Generate keys &amp; enroll
                </PrimaryButton>
              </div>
            </form>
          </div>
        </div>
      )}
    </PageShell>
  );
};
