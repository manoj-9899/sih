import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  CheckCircle2,
  XCircle,
  Clock,
  User,
  Key,
  Package,
  FileText,
  Database,
  Lock,
  Unlock,
  ExternalLink,
  ChevronRight,
  Send,
  UserX,
  FileSpreadsheet,
  Camera,
  Archive,
  Check,
} from 'lucide-react';
import {
  SecurityIncident,
  IncidentStatus,
  ContainmentActionType,
} from '../types/incident';
import { securityIncidentEngine } from '../services/incidentEngine';
import { AuditEvent } from '../types/audit';
import { KeyValueRow, PrimaryButton, SecondaryButton } from './ui/designSystem';
import { ForensicDossierModal } from './ForensicDossierModal';

interface IncidentResponseDrawerProps {
  incident: SecurityIncident;
  onClose: () => void;
  onIncidentUpdated: () => void;
  allAuditEvents: AuditEvent[];
  onNavigateToLedger?: () => void;
  onNavigateToForensics?: () => void;
}

export const IncidentResponseDrawer: React.FC<IncidentResponseDrawerProps> = ({
  incident,
  onClose,
  onIncidentUpdated,
  allAuditEvents,
  onNavigateToLedger,
  onNavigateToForensics,
}) => {
  const [newStatus, setNewStatus] = useState<IncidentStatus>(incident.status);
  const [statusReason, setStatusReason] = useState<string>('');
  const [newNote, setNewNote] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [actionSuccessMsg, setActionSuccessMsg] = useState<string | null>(null);
  const [showDossierModal, setShowDossierModal] = useState<boolean>(false);

  // Filter authentic audit records linked as evidence
  const linkedAuditEvents = allAuditEvents.filter((e) =>
    incident.evidenceEventIds.includes(e.eventId)
  );

  const handleStatusChange = async () => {
    if (newStatus === incident.status) return;
    setIsSubmitting(true);
    try {
      await securityIncidentEngine.transitionIncidentStatus(
        incident.incidentId,
        newStatus,
        'SOC_INVESTIGATOR_01',
        statusReason || `Status updated to ${newStatus}`
      );
      setStatusReason('');
      onIncidentUpdated();
      setActionSuccessMsg(`Status updated to ${newStatus}`);
      setTimeout(() => setActionSuccessMsg(null), 3000);
    } catch (e: any) {
      console.error('[IncidentDrawer] Transition failed:', e);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleAddNote = async () => {
    if (!newNote.trim()) return;
    setIsSubmitting(true);
    try {
      await securityIncidentEngine.addNote(
        incident.incidentId,
        'SOC_INVESTIGATOR_01',
        'Lead Security Investigator',
        newNote.trim()
      );
      setNewNote('');
      onIncidentUpdated();
      setActionSuccessMsg('Investigation note recorded.');
      setTimeout(() => setActionSuccessMsg(null), 3000);
    } catch (e: any) {
      console.error('[IncidentDrawer] Failed to add note:', e);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleExecuteContainment = async (actionType: ContainmentActionType) => {
    setIsSubmitting(true);
    try {
      const res = await securityIncidentEngine.executeContainmentAction(
        incident.incidentId,
        actionType,
        'SOC_INVESTIGATOR_01',
        'Lead Security Investigator'
      );
      onIncidentUpdated();
      setActionSuccessMsg(res.details);
      setTimeout(() => setActionSuccessMsg(null), 4000);
    } catch (e: any) {
      console.error('[IncidentDrawer] Containment action failed:', e);
    } finally {
      setIsSubmitting(false);
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 border border-rose-300">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-100 text-amber-800 border border-amber-300">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-50 text-amber-700 border border-amber-200">MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-600 bg-slate-100 border border-slate-200">LOW</span>;
    }
  };

  const getConfidenceBadge = (conf: string) => {
    switch (conf) {
      case 'CERTAIN':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">CONFIDENCE: CERTAIN (PROOF)</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-100 text-indigo-800 border border-indigo-300">CONFIDENCE: HIGH</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-600 bg-slate-100 border border-slate-200">CONFIDENCE: {conf}</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-2xs flex justify-end animate-in fade-in">
      <div className="w-full max-w-2xl bg-white h-full shadow-2xl flex flex-col">
        {/* Top Header */}
        <div className="p-6 border-b border-slate-200 flex items-start justify-between bg-slate-50/50">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-indigo-600">{incident.incidentId}</span>
              {getSeverityBadge(incident.severity)}
              {getConfidenceBadge(incident.confidence)}
            </div>
            <h2 className="text-base font-bold text-slate-900">{incident.title}</h2>
            <div className="text-[11px] font-mono text-slate-500">
              Rule: {incident.detectionRuleName} ({incident.ruleId})
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-700 text-sm font-bold cursor-pointer"
          >
            ✕
          </button>
        </div>

        {/* Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {actionSuccessMsg && (
            <div className="p-3 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-lg text-xs flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
              <span>{actionSuccessMsg}</span>
            </div>
          )}

          {/* Incident Status Management */}
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
            <span className="text-xs font-bold text-slate-800 uppercase tracking-wider block">
              Incident Triage & Lifecycle State
            </span>
            <div className="flex flex-wrap items-center gap-2">
              {(['OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'] as IncidentStatus[]).map(
                (st) => (
                  <button
                    key={st}
                    type="button"
                    onClick={() => setNewStatus(st)}
                    className={`px-3 py-1 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer ${
                      newStatus === st
                        ? 'bg-indigo-600 text-white shadow-2xs'
                        : 'bg-white border border-slate-200 text-slate-600 hover:bg-slate-100'
                    }`}
                  >
                    {st}
                  </button>
                )
              )}
            </div>
            {newStatus !== incident.status && (
              <div className="pt-2 flex flex-col sm:flex-row gap-2">
                <input
                  type="text"
                  placeholder="Mandatory justification/reason for status update..."
                  value={statusReason}
                  onChange={(e) => setStatusReason(e.target.value)}
                  className="flex-1 px-3 py-1.5 text-xs bg-white border border-slate-200 rounded-lg font-mono focus:outline-hidden focus:border-indigo-500"
                />
                <PrimaryButton size="sm" onClick={handleStatusChange} disabled={isSubmitting}>
                  Confirm Status Change
                </PrimaryButton>
              </div>
            )}
          </div>

          {/* Context Details */}
          <div className="space-y-2 text-xs">
            <KeyValueRow label="First Observed" value={new Date(incident.firstObservedAt).toLocaleString()} />
            <KeyValueRow label="Last Observed" value={new Date(incident.lastObservedAt).toLocaleString()} />
            <KeyValueRow
              label="Applied Threshold"
              value={`≥${incident.thresholdApplied.minOccurrences} in ${Math.round(incident.thresholdApplied.timeWindowMs / 60000)}m (Found ${incident.thresholdApplied.actualOccurrences})`}
            />
            {incident.affectedRecipientId && (
              <KeyValueRow label="Target Recipient" value={`${incident.affectedRecipientName || ''} (${incident.affectedRecipientId})`} />
            )}
            {incident.affectedPackageId && (
              <KeyValueRow label="Target Container" value={incident.affectedPackageId} />
            )}
            {incident.affectedDocumentId && (
              <KeyValueRow label="Target Document" value={incident.affectedDocumentId} />
            )}
          </div>

          {/* Description */}
          <div className="space-y-1">
            <span className="text-xs font-semibold text-slate-700">Threat Assessment:</span>
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-800 font-mono">
              {incident.description}
            </div>
          </div>

          {/* Verified Evidence Trail */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                Cryptographic Evidence Chain ({linkedAuditEvents.length} Verified Records)
              </span>
              <span className="text-[10px] font-mono text-slate-400">
                Consistency Digest: {incident.evidenceDigest.slice(0, 12)}...
              </span>
            </div>

            <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
              {linkedAuditEvents.map((evt) => (
                <div key={evt.eventId} className="p-2.5 bg-white border border-slate-200 rounded-lg text-xs space-y-1">
                  <div className="flex items-center justify-between font-mono text-[11px]">
                    <span className="font-bold text-slate-800">{evt.eventType}</span>
                    <span className="text-slate-400">{new Date(evt.timestampEpochMs).toLocaleTimeString()}</span>
                  </div>
                  <p className="text-slate-600 text-[11px] truncate">{evt.description}</p>
                  <div className="text-[10px] font-mono text-slate-400 truncate">
                    Event Digest: {evt.eventHash?.slice(0, 24)}...
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Containment & Response Actions */}
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
            <span className="text-xs font-bold text-slate-800 uppercase tracking-wider block">
              Active Incident Containment Actions
            </span>
            <div className="flex flex-wrap gap-2">
              {incident.affectedRecipientId && (
                <SecondaryButton
                  size="sm"
                  icon={<UserX className="w-3.5 h-3.5 text-rose-600" />}
                  onClick={() => handleExecuteContainment('REVOKE_RECIPIENT')}
                  disabled={isSubmitting}
                >
                  Revoke Recipient Clearance
                </SecondaryButton>
              )}

              {incident.affectedPackageId && (
                <SecondaryButton
                  size="sm"
                  icon={<Archive className="w-3.5 h-3.5 text-amber-600" />}
                  onClick={() => handleExecuteContainment('FLAG_PACKAGE_ISOLATED')}
                  disabled={isSubmitting}
                >
                  Flag & Quarantine Container
                </SecondaryButton>
              )}

              <SecondaryButton
                size="sm"
                icon={<Camera className="w-3.5 h-3.5 text-indigo-600" />}
                onClick={() => handleExecuteContainment('RECORD_FORENSIC_SNAPSHOT')}
                disabled={isSubmitting}
              >
                Record Forensic Snapshot
              </SecondaryButton>

              <PrimaryButton
                size="sm"
                icon={<FileText className="w-3.5 h-3.5" />}
                onClick={() => setShowDossierModal(true)}
              >
                Generate & Inspect Dossier
              </PrimaryButton>

              {onNavigateToLedger && (
                <SecondaryButton
                  size="sm"
                  icon={<Database className="w-3.5 h-3.5 text-blue-600" />}
                  onClick={onNavigateToLedger}
                >
                  Inspect DLT Ledger
                </SecondaryButton>
              )}
            </div>

            {/* Response Action History */}
            {incident.responseActions.length > 0 && (
              <div className="space-y-1.5 pt-2 border-t border-slate-200">
                <span className="text-[11px] font-semibold text-slate-600 block">Executed Actions:</span>
                {incident.responseActions.map((act) => (
                  <div key={act.actionId} className="p-2 bg-white border border-slate-200 rounded text-[11px] flex items-center justify-between">
                    <div>
                      <span className="font-mono font-bold text-slate-800">{act.actionType}</span> &bull; {act.details}
                    </div>
                    <span className="text-emerald-700 font-mono font-semibold">{act.outcome}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Investigation Notes & Collaboration */}
          <div className="space-y-2">
            <span className="text-xs font-bold text-slate-800 uppercase tracking-wider block">
              Investigator Field Notes
            </span>
            <div className="space-y-2">
              {incident.investigatorNotes.map((note) => (
                <div key={note.noteId} className="p-3 bg-white border border-slate-200 rounded-lg text-xs space-y-1">
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
                    <span className="font-semibold text-slate-800">{note.authorDisplayName}</span>
                    <span>{new Date(note.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <p className="text-slate-700">{note.text}</p>
                </div>
              ))}
            </div>

            <div className="flex gap-2 pt-2">
              <input
                type="text"
                placeholder="Add investigation observation or containment note..."
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                className="flex-1 px-3 py-1.5 text-xs bg-white border border-slate-200 rounded-lg font-mono focus:outline-hidden focus:border-indigo-500"
              />
              <PrimaryButton size="sm" icon={<Send className="w-3.5 h-3.5" />} onClick={handleAddNote} disabled={isSubmitting || !newNote.trim()}>
                Post Note
              </PrimaryButton>
            </div>
          </div>
        </div>
      </div>

      {/* FORENSIC INVESTIGATION DOSSIER MODAL */}
      {showDossierModal && (
        <ForensicDossierModal
          incident={incident}
          onClose={() => setShowDossierModal(false)}
          onDossierGenerated={onIncidentUpdated}
        />
      )}
    </div>
  );
};
