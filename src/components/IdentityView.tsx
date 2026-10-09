import React, { useState } from 'react';
import {
  KeyRound,
  ShieldCheck,
  RefreshCw,
  CheckCircle2,
  Lock,
  Layers,
  FileCheck,
} from 'lucide-react';
import {
  PageShell,
  PageHeader,
  Section,
  PrimaryButton,
  SecondaryButton,
  StatusBadge,
  KeyValueRow,
  TechnicalDetails,
} from './ui/designSystem';
import { Recipient } from '../types';
import { generateRecipientPqcKeys, bytesToHex } from '../crypto/pqc';

interface IdentityViewProps {
  recipients: Recipient[];
}

export const IdentityView: React.FC<IdentityViewProps> = ({ recipients }) => {
  const [selectedRecipientId, setSelectedRecipientId] = useState<string>(recipients[0]?.id || '');
  const [isGenerating, setIsGenerating] = useState(false);
  const [testGeneratedKey, setTestGeneratedKey] = useState<{
    kemPubKeyHex: string;
    dsaPubKeyHex: string;
    fingerprint: string;
    generationTimeMs: number;
  } | null>(null);

  const selectedRecipient = recipients.find((r) => r.id === selectedRecipientId) || recipients[0];

  const handleGenerateLivePqcKeys = async () => {
    setIsGenerating(true);
    const start = performance.now();
    try {
      const keys = await generateRecipientPqcKeys();
      const elapsed = performance.now() - start;

      setTestGeneratedKey({
        kemPubKeyHex: bytesToHex(keys.kemPublicKey),
        dsaPubKeyHex: bytesToHex(keys.dsaPublicKey),
        fingerprint: keys.fingerprint,
        generationTimeMs: Math.round(elapsed),
      });
    } catch (err) {
      console.error('PQC generation failed:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <PageShell>
      <PageHeader
        title="Cryptographic identities"
        description="Manage the post-quantum identities used to protect access and verify decryption events."
        action={
          <PrimaryButton
            size="sm"
            icon={<RefreshCw className={`w-3.5 h-3.5 ${isGenerating ? 'animate-spin' : ''}`} />}
            onClick={handleGenerateLivePqcKeys}
            loading={isGenerating}
          >
            Generate test key pair
          </PrimaryButton>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: Identity List */}
        <div className="lg:col-span-5 space-y-4">
          <Section title="Registered identities" description="Active post-quantum key pairs.">
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
                        <div className="text-[10px] text-slate-500 font-mono truncate">
                          FP: {recip.keys.keyFingerprint}
                        </div>
                      </div>
                    </div>

                    <span className="text-[10px] font-mono text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200 font-medium shrink-0">
                      Active
                    </span>
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
              description={`Role: ${selectedRecipient.role}`}
              action={
                <StatusBadge status="verified" icon={<CheckCircle2 className="w-3 h-3 text-emerald-600" />}>
                  Identity verified
                </StatusBadge>
              }
            >
              <div className="space-y-4 pt-1">
                {/* Clean Status Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="p-3.5 bg-slate-50 rounded-lg border border-slate-200/80 space-y-1">
                    <span className="text-[11px] text-slate-500 font-medium block">
                      Key exchange
                    </span>
                    <div className="font-semibold text-slate-900 text-xs">
                      ML-KEM-768
                    </div>
                    <span className="text-[10px] text-slate-500 block">
                      Public key registered (NIST FIPS 203)
                    </span>
                  </div>

                  <div className="p-3.5 bg-slate-50 rounded-lg border border-slate-200/80 space-y-1">
                    <span className="text-[11px] text-slate-500 font-medium block">
                      Digital signature
                    </span>
                    <div className="font-semibold text-slate-900 text-xs">
                      ML-DSA-65
                    </div>
                    <span className="text-[10px] text-slate-500 block">
                      Public key registered (NIST FIPS 204)
                    </span>
                  </div>
                </div>

                {/* Identity Summary Info */}
                <div className="p-3.5 bg-slate-50/70 rounded-lg border border-slate-200/80 space-y-2 text-xs">
                  <div className="flex justify-between text-slate-600">
                    <span>Identity Status:</span>
                    <span className="font-semibold text-slate-900">Enrolled &amp; Active</span>
                  </div>
                  <div className="flex justify-between text-slate-600">
                    <span>Private Key Storage:</span>
                    <span className="font-semibold text-emerald-700">Protected in local keystore</span>
                  </div>
                  <div className="flex justify-between text-slate-600">
                    <span>Key Fingerprint:</span>
                    <span className="font-mono text-slate-800">{selectedRecipient.keys.keyFingerprint}</span>
                  </div>
                </div>

                {/* Progressive Disclosure of Public Keys */}
                <TechnicalDetails title="View public key hex credentials &amp; algorithm parameters">
                  <KeyValueRow label="ML-KEM-768 Public Key (Hex)" value={selectedRecipient.keys.kemPublicKeyHex} copyable />
                  <KeyValueRow label="ML-DSA-65 Public Key (Hex)" value={selectedRecipient.keys.dsaPublicKeyHex} copyable />
                  <div className="pt-2 text-[11px] text-slate-500">
                    Raw private key material is kept strictly isolated in the local client environment and never transmitted across the network.
                  </div>
                </TechnicalDetails>

                {/* Live Test Generated Keypair result if created */}
                {testGeneratedKey && (
                  <div className="p-3.5 rounded-lg bg-indigo-50/70 border border-indigo-200 text-xs space-y-2 animate-in fade-in">
                    <div className="flex justify-between items-center text-indigo-950 font-semibold">
                      <span>Newly Generated Test Key Pair</span>
                      <span className="font-mono text-[10px] bg-white px-2 py-0.5 rounded border border-indigo-200 text-indigo-700">
                        {testGeneratedKey.generationTimeMs} ms
                      </span>
                    </div>
                    <div className="text-[11px] text-indigo-900 font-mono truncate">
                      Fingerprint: {testGeneratedKey.fingerprint}
                    </div>
                  </div>
                )}
              </div>
            </Section>
          ) : null}
        </div>
      </div>
    </PageShell>
  );
};
