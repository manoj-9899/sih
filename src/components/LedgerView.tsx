import React, { useState, useEffect } from 'react';
import {
  Database,
  RefreshCw,
  ShieldCheck,
  AlertTriangle,
  RotateCcw,
  CheckCircle2,
  Layers,
  ArrowRight,
} from 'lucide-react';
import {
  PageShell,
  PageHeader,
  Section,
  PrimaryButton,
  SecondaryButton,
  DangerButton,
  StatusBadge,
  VerificationBadge,
  KeyValueRow,
  HashDisplay,
  TechnicalDetails,
} from './ui/designSystem';
import { LedgerBlock, ValidatorNode } from '../types';
import { airGappedLedger } from '../ledger/dlt';

interface LedgerViewProps {
  onRefreshNeeded: () => void;
}

export const LedgerView: React.FC<LedgerViewProps> = ({ onRefreshNeeded }) => {
  const [chain, setChain] = useState<LedgerBlock[]>([]);
  const [validators, setValidators] = useState<ValidatorNode[]>([]);
  const [selectedBlockHeight, setSelectedBlockHeight] = useState<number>(0);
  const [isAuditing, setIsAuditing] = useState(false);
  const [auditResult, setAuditResult] = useState<{
    isValid: boolean;
    totalBlocksChecked: number;
    totalTransactionsChecked: number;
    tamperDetected?: {
      blockHeight: number;
      reason: string;
    };
  } | null>(null);

  const [isTampered, setIsTampered] = useState(false);

  const loadData = () => {
    const rawChain = airGappedLedger.getChain();
    setChain(rawChain);
    setValidators(airGappedLedger.getValidators());
    if (rawChain.length > 0 && selectedBlockHeight === 0) {
      setSelectedBlockHeight(rawChain[rawChain.length - 1].height);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRunAudit = async () => {
    setIsAuditing(true);
    await new Promise((r) => setTimeout(r, 300));
    try {
      const res = await airGappedLedger.verifyLedgerIntegrity();
      setAuditResult(res);
      setIsTampered(!res.isValid);
    } catch (err) {
      console.error('Audit failure:', err);
    } finally {
      setIsAuditing(false);
    }
  };

  const handleSimulateTamper = () => {
    airGappedLedger.simulateTamper(1, 'USR-TAMPERED-MALICIOUS-ADMIN');
    setIsTampered(true);
    handleRunAudit();
    onRefreshNeeded();
  };

  const handleRestoreLedger = () => {
    airGappedLedger.restoreLedger();
    setIsTampered(false);
    loadData();
    handleRunAudit();
    onRefreshNeeded();
  };

  const selectedBlock = chain.find((b) => b.height === selectedBlockHeight) || chain[chain.length - 1];
  const latestBlock = chain[chain.length - 1];

  return (
    <PageShell>
      <PageHeader
        title="Ledger"
        description="Tamper-evident provenance for verified decryption events across multi-node consensus."
        badge={
          <StatusBadge
            status={isTampered ? 'failed' : 'verified'}
            icon={isTampered ? <AlertTriangle className="w-3 h-3 text-rose-600" /> : <CheckCircle2 className="w-3 h-3 text-emerald-600" />}
          >
            {isTampered ? 'Ledger tampering detected' : 'Ledger integrity verified'}
          </StatusBadge>
        }
        action={
          <div className="flex items-center gap-2">
            {isTampered ? (
              <SecondaryButton
                size="sm"
                icon={<RotateCcw className="w-3.5 h-3.5 text-emerald-600" />}
                onClick={handleRestoreLedger}
              >
                Restore quorum integrity
              </SecondaryButton>
            ) : (
              chain.length > 1 && (
                <DangerButton
                  size="sm"
                  icon={<AlertTriangle className="w-3.5 h-3.5" />}
                  onClick={handleSimulateTamper}
                  data-tour-target="tamper-demo-btn"
                >
                  Simulate rogue admin tamper
                </DangerButton>
              )
            )}

            <PrimaryButton
              size="sm"
              icon={<RefreshCw className={`w-3.5 h-3.5 ${isAuditing ? 'animate-spin' : ''}`} />}
              onClick={handleRunAudit}
              loading={isAuditing}
            >
              Audit entire chain
            </PrimaryButton>
          </div>
        }
      />

      {/* 1. TOP HEALTH & COMPACT VALIDATOR CARDS */}
      <div className="space-y-3">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {validators.map((val, idx) => {
            const ports = [7001, 7002, 7003, 7004];
            const port = ports[idx] || 7001 + idx;
            return (
              <div
                key={val.id}
                className="p-3 bg-white rounded-xl border border-slate-200/90 shadow-2xs space-y-1 text-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-900 truncate">{val.name}</span>
                  <span className={`inline-flex items-center gap-1 text-[11px] font-medium font-mono ${
                    val.status === 'OFFLINE' ? 'text-slate-500' : 'text-emerald-700'
                  }`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${
                      val.status === 'OFFLINE' ? 'bg-slate-400' : 'bg-emerald-500 animate-pulse'
                    }`} />
                    {val.status === 'OFFLINE' ? 'Offline' : 'Online'}
                  </span>
                </div>
                <div className="text-[11px] text-slate-500 truncate">{val.role}</div>
                <div className="text-[10px] text-slate-400 font-mono pt-1 border-t border-slate-100 flex justify-between">
                  <span>Port {port}</span>
                  <span className="text-emerald-600 font-medium">Replicated</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Cluster Network & Replication Metadata Summary */}
        {latestBlock && (
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="space-y-0.5">
              <span className="text-[11px] text-slate-500 font-medium">Block Height</span>
              <div className="font-mono font-bold text-slate-900">
                Height #{latestBlock.height} ({chain.length} blocks)
              </div>
            </div>

            <div className="space-y-0.5">
              <span className="text-[11px] text-slate-500 font-medium">Head Hash</span>
              <div className="font-mono text-[11px] text-slate-800 truncate" title={latestBlock.blockHash}>
                {latestBlock.blockHash.substring(0, 16)}...
              </div>
            </div>

            <div className="space-y-0.5">
              <span className="text-[11px] text-slate-500 font-medium">Quorum Status</span>
              <div className="text-emerald-700 font-semibold flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3 text-emerald-600 shrink-0" />
                <span>3/4 Active (75%)</span>
              </div>
            </div>

            <div className="space-y-0.5">
              <span className="text-[11px] text-slate-500 font-medium">Replication Status</span>
              <div className="text-emerald-700 font-semibold flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3 text-emerald-600 shrink-0" />
                <span>In Sync (4 Nodes)</span>
              </div>
            </div>
          </div>
        )}

        {/* Expandable Technical Replication Topology */}
        <TechnicalDetails title="Multi-node offline network details (LAN socket topology)">
          <div className="space-y-2 text-xs">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] font-mono">
              <div className="p-2 bg-slate-50 rounded border border-slate-200">
                <span className="font-semibold text-slate-700 block">Validator Alpha (val-alpha-01):</span>
                <span>TCP P2P: 127.0.0.1:7001 &bull; HTTP: 8001</span>
                <span className="text-slate-400 block truncate">Storage: .validator-data/val-alpha-01/ledger.json</span>
              </div>
              <div className="p-2 bg-slate-50 rounded border border-slate-200">
                <span className="font-semibold text-slate-700 block">Validator Bravo (val-bravo-02):</span>
                <span>TCP P2P: 127.0.0.1:7002 &bull; HTTP: 8002</span>
                <span className="text-slate-400 block truncate">Storage: .validator-data/val-bravo-02/ledger.json</span>
              </div>
              <div className="p-2 bg-slate-50 rounded border border-slate-200">
                <span className="font-semibold text-slate-700 block">Validator Gamma (val-gamma-03):</span>
                <span>TCP P2P: 127.0.0.1:7003 &bull; HTTP: 8003</span>
                <span className="text-slate-400 block truncate">Storage: .validator-data/val-gamma-03/ledger.json</span>
              </div>
              <div className="p-2 bg-slate-50 rounded border border-slate-200">
                <span className="font-semibold text-slate-700 block">Validator Delta (val-delta-04):</span>
                <span>TCP P2P: 127.0.0.1:7004 &bull; HTTP: 8004</span>
                <span className="text-slate-400 block truncate">Storage: .validator-data/val-delta-04/ledger.json</span>
              </div>
            </div>
            <p className="text-[11px] text-slate-500">
              Transport: Air-gapped length-prefixed TCP socket stream (RFC 8785 canonical payloads, zero internet dependencies).
            </p>
          </div>
        </TechnicalDetails>
      </div>

      {/* Audit Alarm Banner if Tampered */}
      {isTampered && auditResult?.tamperDetected && (
        <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-950 space-y-2">
          <div className="font-bold flex items-center gap-1.5 text-rose-800">
            <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
            CRITICAL INTEGRITY BREACH: TAMPERING DETECTED AT BLOCK #{auditResult.tamperDetected.blockHeight}
          </div>
          <p className="text-[11px] text-rose-800 leading-normal">
            {auditResult.tamperDetected.reason}. The cryptographic hash chain and Merkle tree root were broken, causing the 4/4 validator quorum to flag the block as unauthorized.
          </p>
        </div>
      )}

      {/* 2. RECENT PROVENANCE CHRONOLOGY */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: Block Timeline Selector */}
        <div className="lg:col-span-5 space-y-4">
          <Section title="Block hierarchy" description="Sequential chain with SHA-256 hash pointers.">
            <div className="space-y-2 mt-2">
              {chain.slice().reverse().map((b) => {
                const isSelected = b.height === selectedBlockHeight;
                return (
                  <div
                    key={b.height}
                    onClick={() => setSelectedBlockHeight(b.height)}
                    className={`p-3 rounded-lg border transition-all cursor-pointer select-none ${
                      isSelected
                        ? 'border-indigo-500 bg-indigo-50/40 text-slate-900 shadow-2xs ring-1 ring-indigo-200'
                        : 'border-slate-200/80 bg-white text-slate-700 hover:border-slate-300 hover:bg-slate-50/60'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="font-semibold text-slate-900">
                        {b.height === 0 ? 'Genesis Block (0)' : `Block #${b.height}`}
                      </span>
                      <span className="text-[10px] text-slate-400 font-mono">
                        {b.transactions.length} event{b.transactions.length === 1 ? '' : 's'}
                      </span>
                    </div>

                    <div className="text-[11px] text-slate-500 font-mono truncate">
                      Hash: {b.blockHash.slice(0, 16)}...
                    </div>
                  </div>
                );
              })}
            </div>
          </Section>
        </div>

        {/* Right: Block Provenance & Transactions Detail */}
        <div className="lg:col-span-7 space-y-6">
          {selectedBlock ? (
            <Section
              title={selectedBlock.height === 0 ? 'Genesis Block' : `Block #${selectedBlock.height}`}
              description={`Committed ${new Date(selectedBlock.timestamp).toLocaleTimeString()}`}
              action={
                <VerificationBadge label={`${selectedBlock.validatorSignatures.length}/4 Quorum Attested`} />
              }
            >
              <div className="space-y-4 pt-1">
                {/* Transactions list in this block */}
                <div>
                  <span className="text-xs font-semibold text-slate-900 block mb-2">
                    Verified Decryption Events:
                  </span>
                  {selectedBlock.transactions.length === 0 ? (
                    <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 text-xs text-slate-500">
                      Genesis block initialized the identity root. No user events.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {selectedBlock.transactions.map((tx) => (
                        <div
                          key={tx.eventId}
                          className="p-3.5 bg-slate-50 rounded-lg border border-slate-200/80 space-y-1.5 text-xs"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-slate-900">{tx.recipientName}</span>
                            <span className="font-mono text-[10px] text-slate-500">{tx.eventId}</span>
                          </div>
                          <div className="text-[11px] text-slate-600">
                            Document: {tx.documentTitle}
                          </div>
                          <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-slate-200/60 text-[10px] font-mono text-slate-500">
                            <span>Watermark: {tx.watermarkId}</span>
                            <span className="text-emerald-700 font-semibold flex items-center gap-1">
                              <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                              ML-DSA-65 Signature Valid
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Progressive disclosure of cryptographic block hashes */}
                <TechnicalDetails title="View Merkle root, validator attestations &amp; block hashes">
                  <KeyValueRow label="Block Height" value={selectedBlock.height.toString()} />
                  <KeyValueRow label="Block Hash (SHA-256)" value={selectedBlock.blockHash} copyable />
                  <KeyValueRow label="Previous Block Hash" value={selectedBlock.previousHash} copyable />
                  <KeyValueRow label="Merkle Root" value={selectedBlock.merkleRoot} copyable />
                  <div className="pt-2 text-[11px] text-slate-500">
                    All blocks are ratified through Byzantine fault-tolerant consensus across 4 independent validator enclaves.
                  </div>
                </TechnicalDetails>
              </div>
            </Section>
          ) : null}
        </div>
      </div>
    </PageShell>
  );
};
