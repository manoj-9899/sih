import React from 'react';
import {
  Settings,
  Shield,
  Database,
  Layers,
  CheckCircle2,
  RotateCcw,
} from 'lucide-react';
import {
  PageShell,
  PageHeader,
  Section,
  PrimaryButton,
  SecondaryButton,
  StatusBadge,
  VerificationBadge,
  KeyValueRow,
} from './ui/designSystem';

interface SettingsViewProps {
  onResetSession: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ onResetSession }) => {
  return (
    <PageShell>
      <PageHeader
        title="Settings"
        description="System configuration, air-gap boundary, and consensus parameters."
      />

      <div className="space-y-6">
        {/* 1. Environment & Network Isolation */}
        <Section title="Environment configuration" description="Execution boundary and storage model.">
          <div className="space-y-3 pt-1">
            <KeyValueRow
              label="Network Mode"
              value="Air-Gapped / Isolated (No external outbound telemetry)"
              mono={false}
            />
            <KeyValueRow
              label="Storage Adapter"
              value="Local IndexedDB (Persistent local browser partition)"
              mono={false}
            />
            <KeyValueRow
              label="Session Boundary"
              value="Local security environment"
              mono={false}
            />
          </div>
        </Section>

        {/* 2. Cryptographic Parameter Set */}
        <Section title="Cryptographic configuration" description="Active post-quantum standards.">
          <div className="space-y-3 pt-1">
            <KeyValueRow
              label="Key Encapsulation Mechanism"
              value="NIST FIPS 203 (ML-KEM-768) - Lattice Cryptography"
              mono={false}
            />
            <KeyValueRow
              label="Digital Signature Standard"
              value="NIST FIPS 204 (ML-DSA-65) - Lattice Signature"
              mono={false}
            />
            <KeyValueRow
              label="Bulk Symmetric Cipher"
              value="AES-256-GCM (96-bit IV, 128-bit authentication tag)"
              mono={false}
            />
            <KeyValueRow
              label="Key Derivation Function"
              value="HKDF-SHA256 (RFC 5869)"
              mono={false}
            />
          </div>
        </Section>

        {/* 3. Ledger & Consensus Parameters */}
        <Section title="Consensus configuration" description="Byzantine fault tolerance parameters.">
          <div className="space-y-3 pt-1">
            <KeyValueRow
              label="Consensus Architecture"
              value="Permissioned Quorum (3/4 Node Threshold)"
              mono={false}
            />
            <KeyValueRow
              label="Active Validator Enclaves"
              value="Alpha (Vault-1), Bravo (Hub-B), Gamma (Operations), Delta (Secondary)"
              mono={false}
            />
            <KeyValueRow
              label="Hash Chaining"
              value="SHA-256 with binary Merkle root state transitions"
              mono={false}
            />
          </div>
        </Section>

        {/* 4. Maintenance & Reset */}
        <Section title="System management" description="Local session state and repository maintenance.">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-1 text-xs">
            <div className="space-y-0.5">
              <span className="font-semibold text-slate-900 block">
                Reset local demonstration session
              </span>
              <p className="text-[11px] text-slate-500">
                Clears active packages and resets demo leak simulations back to pristine initial state.
              </p>
            </div>

            <SecondaryButton
              size="sm"
              icon={<RotateCcw className="w-3.5 h-3.5 text-slate-500" />}
              onClick={onResetSession}
            >
              Reset demo session
            </SecondaryButton>
          </div>
        </Section>
      </div>
    </PageShell>
  );
};
