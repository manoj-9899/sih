import React, { useState, useEffect } from 'react';
import {
  FileText,
  Lock,
  Search,
  ArrowRight,
  AlertTriangle,
  Users,
  ShieldCheck,
  FileCheck,
} from 'lucide-react';
import {
  PageShell,
  PageHeader,
  Section,
  PrimaryButton,
  SecondaryButton,
  EmptyState,
} from './ui/designSystem';
import { ClassifiedDocument, Recipient, EncryptedPackage, DocumentAssignment } from '../types';
import { ActiveTab } from '../types/navigation';
import { airGappedLedger } from '../ledger/dlt';
import { sessionManager, AuthenticatedSession } from '../crypto/sessionManager';
import { airGappedStorage } from '../storage/airGappedStorage';
import { auditService } from '../services/auditService';
import { AuditEvent } from '../types/audit';

interface OverviewViewProps {
  documents: ClassifiedDocument[];
  recipients: Recipient[];
  activePackage: EncryptedPackage | null;
  onNavigateTab: (tab: ActiveTab) => void;
}

interface ActivityItem {
  id: string;
  description: string;
  actor?: string;
  formattedTime: string;
  statusText: string;
  statusColor: string;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  documents,
  recipients,
  activePackage,
  onNavigateTab,
}) => {
  const chain = airGappedLedger.getChain();

  const [activeSession, setActiveSession] = useState<AuthenticatedSession | null>(() =>
    sessionManager.getActiveSession()
  );
  const [assignments, setAssignments] = useState<DocumentAssignment[]>([]);
  const [recentActivities, setRecentActivities] = useState<ActivityItem[]>([]);
  const [isLoadingActivity, setIsLoadingActivity] = useState<boolean>(true);

  // Subscribe to live session changes
  useEffect(() => {
    return sessionManager.subscribe((session) => {
      setActiveSession(session);
    });
  }, []);

  // Fetch real assignments and recent activity
  useEffect(() => {
    let isMounted = true;

    const loadData = async () => {
      try {
        setIsLoadingActivity(true);
        const [asgns, events] = await Promise.all([
          airGappedStorage.getAssignments().catch(() => []),
          auditService.queryEvents({}).catch(() => []),
        ]);

        if (!isMounted) return;
        setAssignments(asgns || []);

        // Derive recent activities from audit events or ledger events
        if (events && events.length > 0) {
          const sorted = [...events]
            .sort((a, b) => b.timestampEpochMs - a.timestampEpochMs)
            .slice(0, 5);

          const items: ActivityItem[] = sorted.map((ev: AuditEvent) => ({
            id: ev.eventId,
            description: ev.description || ev.action || 'Cryptographic operation recorded',
            actor: ev.actor?.displayName || ev.actor?.id,
            formattedTime: new Date(ev.timestampEpochMs).toLocaleTimeString([], {
              hour: '2-digit',
              minute: '2-digit',
            }) + ' · ' + new Date(ev.timestampEpochMs).toLocaleDateString(),
            statusText:
              ev.outcome === 'SUCCESS'
                ? ev.dltAnchored
                  ? 'Ledger anchored'
                  : 'Completed'
                : ev.outcome === 'FAILURE'
                ? 'Failed'
                : 'Denied',
            statusColor:
              ev.outcome === 'SUCCESS'
                ? 'text-emerald-700'
                : ev.outcome === 'FAILURE'
                ? 'text-rose-700'
                : 'text-amber-700',
          }));
          setRecentActivities(items);
        } else {
          // Fallback to ledger block transactions if audit service is empty
          const ledgerTransactions = chain.flatMap((b) => b.transactions);
          if (ledgerTransactions.length > 0) {
            const sorted = [...ledgerTransactions]
              .sort((a, b) => b.timestampEpochMs - a.timestampEpochMs)
              .slice(0, 5);

            const items: ActivityItem[] = sorted.map((tx) => ({
              id: tx.eventId,
              description: `Decrypted "${tx.documentTitle}" with forensic watermark`,
              actor: tx.recipientName,
              formattedTime: new Date(tx.timestampEpochMs).toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
              }) + ' · ' + new Date(tx.timestampEpochMs).toLocaleDateString(),
              statusText: 'DLT ratified',
              statusColor: 'text-emerald-700',
            }));
            setRecentActivities(items);
          } else {
            setRecentActivities([]);
          }
        }
      } catch (err) {
        console.warn('[OverviewView] Failed to query activity:', err);
      } finally {
        if (isMounted) setIsLoadingActivity(false);
      }
    };

    loadData();
    return () => {
      isMounted = false;
    };
  }, [chain.length, activePackage?.packageId]);

  // Evaluate genuine security notice conditions
  const revokedAssignments = assignments.filter((a) => a.status === 'REVOKED');
  const packageTrackingFailed = activePackage?.trackingStatus === 'TRACKING_FAILED';
  const uninitializedLedger = chain.length === 0;

  return (
    <PageShell>
      {/* A. PAGE HEADING */}
      <PageHeader
        title="Overview"
        description="Securely distribute post-quantum encrypted documents and verify recipient-specific provenance."
        action={
          <PrimaryButton
            size="sm"
            icon={<FileText className="w-3.5 h-3.5" />}
            onClick={() => onNavigateTab('documents')}
          >
            Start distribution
          </PrimaryButton>
        }
      />

      {/* E. OPTIONAL CONTEXTUAL SECURITY NOTICE (Only rendered if genuine anomaly exists) */}
      {revokedAssignments.length > 0 ? (
        <div className="p-3.5 rounded-xl bg-amber-50/90 border border-amber-200 text-xs text-amber-900 flex items-center justify-between gap-3 animate-in fade-in">
          <div className="flex items-center gap-2.5 min-w-0">
            <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
            <span className="truncate">
              <strong>Security notice:</strong> {revokedAssignments.length} recipient {revokedAssignments.length === 1 ? 'assignment has' : 'assignments have'} been revoked. Decryption for affected packages is forbidden.
            </span>
          </div>
          <button
            onClick={() => onNavigateTab('recipients')}
            className="text-xs font-semibold text-amber-800 hover:text-amber-950 underline shrink-0 cursor-pointer"
          >
            Review recipients
          </button>
        </div>
      ) : packageTrackingFailed ? (
        <div className="p-3.5 rounded-xl bg-amber-50/90 border border-amber-200 text-xs text-amber-900 flex items-center justify-between gap-3 animate-in fade-in">
          <div className="flex items-center gap-2.5 min-w-0">
            <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
            <span className="truncate">
              <strong>Distribution tracking alert:</strong> Tracking failed for package "{activePackage?.documentTitle}". Encrypted packages remain preserved offline.
            </span>
          </div>
          <button
            onClick={() => onNavigateTab('audit')}
            className="text-xs font-semibold text-amber-800 hover:text-amber-950 underline shrink-0 cursor-pointer"
          >
            View audit logs
          </button>
        </div>
      ) : uninitializedLedger ? (
        <div className="p-3.5 rounded-xl bg-slate-100 border border-slate-200 text-xs text-slate-800 flex items-center justify-between gap-3 animate-in fade-in">
          <div className="flex items-center gap-2.5 min-w-0">
            <AlertTriangle className="w-4 h-4 text-slate-500 shrink-0" />
            <span className="truncate">
              <strong>Ledger status:</strong> Genesis block is not yet initialized. Provenance recording is on standby.
            </span>
          </div>
          <button
            onClick={() => onNavigateTab('ledger')}
            className="text-xs font-semibold text-slate-700 hover:text-slate-900 underline shrink-0 cursor-pointer"
          >
            Open ledger
          </button>
        </div>
      ) : null}

      {/* B. ESSENTIAL SYSTEM STATUS (Compact horizontal row) */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3.5 bg-white rounded-xl border border-slate-200/90 text-xs shadow-2xs">
        {/* 1. Cryptographic System Status */}
        <div className="flex items-center gap-2.5 min-w-0">
          <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
          <div className="min-w-0">
            <div className="text-[11px] text-slate-500">Cryptographic System</div>
            <div className="font-semibold text-slate-900 truncate">
              ML-KEM-768 &bull; ML-DSA-65 Active
            </div>
          </div>
        </div>

        {/* 2. Active Session Status */}
        <div className="flex items-center gap-2.5 min-w-0 sm:border-l sm:border-slate-100 sm:pl-3.5">
          {activeSession && activeSession.status === 'ACTIVE' ? (
            <>
              <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
              <div className="min-w-0">
                <div className="text-[11px] text-slate-500">Active Session</div>
                <div className="font-semibold text-slate-900 truncate">
                  {activeSession.userName} ({activeSession.userRole})
                </div>
              </div>
            </>
          ) : (
            <>
              <span className="w-2 h-2 rounded-full bg-amber-500 shrink-0" />
              <div className="min-w-0">
                <div className="text-[11px] text-slate-500">Active Session</div>
                <div className="font-semibold text-slate-700 truncate">
                  Keystore locked &bull; Authentication required
                </div>
              </div>
            </>
          )}
        </div>

        {/* 3. Ledger Status */}
        <div className="flex items-center gap-2.5 min-w-0 sm:border-l sm:border-slate-100 sm:pl-3.5">
          {chain.length > 0 ? (
            <>
              <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
              <div className="min-w-0">
                <div className="text-[11px] text-slate-500">Ledger Verification</div>
                <div className="font-semibold text-slate-900 truncate">
                  {chain.length} {chain.length === 1 ? 'block' : 'blocks'} synchronized (Quorum active)
                </div>
              </div>
            </>
          ) : (
            <>
              <span className="w-2 h-2 rounded-full bg-slate-300 shrink-0" />
              <div className="min-w-0">
                <div className="text-[11px] text-slate-500">Ledger Verification</div>
                <div className="font-semibold text-slate-600 truncate">
                  Uninitialized
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {/* C. PRIMARY ACTION: THREE-STEP WORKFLOW */}
      <Section
        title="Start a Secure Distribution"
        description="Follow the three-step pipeline to encrypt, distribute, and verify document provenance."
        action={
          <SecondaryButton
            size="sm"
            icon={<Search className="w-3.5 h-3.5 text-slate-500" />}
            onClick={() => onNavigateTab('forensics')}
          >
            Forensic analysis
          </SecondaryButton>
        }
      >
        <div className="space-y-4">
          {/* Active In-Flight Package Callout (if present) */}
          {activePackage && (
            <div className="p-3.5 rounded-lg bg-indigo-50/70 border border-indigo-200/90 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-indigo-950">Active distribution:</span>
                  <span className="font-semibold text-slate-900 truncate">{activePackage.documentTitle}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 bg-white rounded border border-indigo-200 text-indigo-700">
                    {activePackage.envelopes.length} {activePackage.envelopes.length === 1 ? 'recipient' : 'recipients'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-600 mt-0.5 truncate">
                  Encrypted package is ready for recipient authentication and provenance-sealed decryption.
                </p>
              </div>
              <PrimaryButton
                size="sm"
                icon={<ArrowRight className="w-3.5 h-3.5" />}
                onClick={() => onNavigateTab('decrypt')}
                className="shrink-0"
              >
                Open in Decrypt
              </PrimaryButton>
            </div>
          )}

          {/* 3-Step Workflow Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
            {/* Step 1 */}
            <div className="p-4 bg-slate-50/60 rounded-xl border border-slate-200/80 flex flex-col justify-between space-y-3">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className="w-5 h-5 rounded-md bg-white border border-slate-200 flex items-center justify-center font-mono text-[11px] font-bold text-slate-700">
                    1
                  </span>
                  <h3 className="text-xs font-semibold text-slate-900">Prepare Document</h3>
                </div>
                <p className="text-[11px] text-slate-600 leading-relaxed">
                  Select a document from the classified catalog ({documents.length} available) or import a defense PDF.
                </p>
              </div>
              <SecondaryButton
                size="sm"
                icon={<FileText className="w-3.5 h-3.5 text-slate-500" />}
                onClick={() => onNavigateTab('documents')}
                className="w-full justify-center"
              >
                Prepare Document
              </SecondaryButton>
            </div>

            {/* Step 2 */}
            <div className="p-4 bg-slate-50/60 rounded-xl border border-slate-200/80 flex flex-col justify-between space-y-3">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className="w-5 h-5 rounded-md bg-white border border-slate-200 flex items-center justify-center font-mono text-xs font-bold text-slate-700">
                    2
                  </span>
                  <h3 className="text-xs font-semibold text-slate-900">Encrypt &amp; Assign</h3>
                </div>
                <p className="text-[11px] text-slate-600 leading-relaxed">
                  Wrap AES-256 payload keys for enrolled recipients ({recipients.length} enrolled) using ML-KEM-768.
                </p>
              </div>
              <SecondaryButton
                size="sm"
                icon={<Users className="w-3.5 h-3.5 text-slate-500" />}
                onClick={() => onNavigateTab('recipients')}
                className="w-full justify-center"
              >
                Review Recipients
              </SecondaryButton>
            </div>

            {/* Step 3 */}
            <div className="p-4 bg-slate-50/60 rounded-xl border border-slate-200/80 flex flex-col justify-between space-y-3">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className="w-5 h-5 rounded-md bg-white border border-slate-200 flex items-center justify-center font-mono text-xs font-bold text-slate-700">
                    3
                  </span>
                  <h3 className="text-xs font-semibold text-slate-900">Verify Provenance</h3>
                </div>
                <p className="text-[11px] text-slate-600 leading-relaxed">
                  Decrypt with recipient-bound watermarking, export signed receipts, and verify provenance.
                </p>
              </div>
              <PrimaryButton
                size="sm"
                icon={<Lock className="w-3.5 h-3.5" />}
                onClick={() => onNavigateTab('decrypt')}
                className="w-full justify-center"
              >
                Decrypt &amp; Receipts
              </PrimaryButton>
            </div>
          </div>
        </div>
      </Section>

      {/* D. RECENT ACTIVITY */}
      <Section
        title="Recent Activity"
        description="Latest cryptographic events attested in local air-gapped storage and ledger blocks."
        action={
          <button
            onClick={() => onNavigateTab('audit')}
            className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 flex items-center gap-1 cursor-pointer transition-colors"
          >
            <span>View audit center</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        }
      >
        {isLoadingActivity ? (
          <div className="py-8 text-center text-xs text-slate-400 flex items-center justify-center gap-2">
            <div className="w-4 h-4 border-2 border-indigo-600 border-t-transparent rounded-full animate-spin" />
            <span>Loading activity log...</span>
          </div>
        ) : recentActivities.length === 0 ? (
          <EmptyState
            title="No activity recorded yet"
            description="Recent cryptographic distributions, recipient decryptions, and verified receipts will appear here."
            action={
              <SecondaryButton
                size="sm"
                onClick={() => onNavigateTab('documents')}
              >
                Start your first distribution
              </SecondaryButton>
            }
          />
        ) : (
          <div className="divide-y divide-slate-100 -mx-4 -mb-4 sm:-mx-6 sm:-mb-6">
            {recentActivities.map((item) => (
              <div
                key={item.id}
                className="px-4 sm:px-6 py-3 flex items-center justify-between gap-4 hover:bg-slate-50/60 transition-colors text-xs"
              >
                <div className="min-w-0 space-y-0.5">
                  <div className="font-semibold text-slate-900 truncate">
                    {item.description}
                  </div>
                  <div className="text-[11px] text-slate-500 truncate flex items-center gap-2">
                    {item.actor && <span>{item.actor}</span>}
                    {item.actor && <span className="text-slate-300">&bull;</span>}
                    <span>{item.formattedTime}</span>
                  </div>
                </div>

                <div className="shrink-0">
                  <span className={`text-[11px] font-semibold ${item.statusColor}`}>
                    {item.statusText}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>
    </PageShell>
  );
};
