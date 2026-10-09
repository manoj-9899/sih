import React, { useState, useEffect } from 'react';
import {
  Activity,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  FileText,
  Database,
  Layers,
  Search,
  Filter,
  Download,
  CheckCircle2,
  XCircle,
  Clock,
  User,
  Key,
  Lock,
  Unlock,
  Package,
  Award,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  ExternalLink,
  Copy,
  Check,
  Eye,
  SlidersHorizontal,
  Flame,
  FileCode,
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
  TechnicalDetails,
} from './ui/designSystem';
import {
  AuditEvent,
  AuditChainVerificationResult,
  SecurityAlert,
  AuditQueryFilter,
  AuditCategory,
  AuditSeverity,
  AuditOutcome,
} from '../types/audit';
import { auditService } from '../services/auditService';
import { securityIncidentEngine } from '../services/incidentEngine';
import { SecurityIncident, IncidentStatus } from '../types/incident';
import { IncidentResponseDrawer } from './IncidentResponseDrawer';
import { airGappedLedger } from '../ledger/dlt';
import { ClassifiedDocument, Recipient } from '../types';

interface AuditCenterViewProps {
  documents?: ClassifiedDocument[];
  recipients?: Recipient[];
  onNavigateToLedger?: () => void;
  onNavigateToForensics?: () => void;
}

export const AuditCenterView: React.FC<AuditCenterViewProps> = ({
  documents = [],
  recipients = [],
  onNavigateToLedger,
  onNavigateToForensics,
}) => {
  // Navigation sub-tabs
  const [subTab, setSubTab] = useState<'timeline' | 'alerts' | 'document_lifecycle' | 'integrity'>('timeline');

  // Audit data
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncident | null>(null);
  const [incidentStatusFilter, setIncidentStatusFilter] = useState<IncidentStatus | 'ALL'>('ALL');
  const [chainResult, setChainResult] = useState<AuditChainVerificationResult | null>(null);
  const [isVerifyingChain, setIsVerifyingChain] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Filters & Search
  const [categoryFilter, setCategoryFilter] = useState<AuditCategory | 'ALL'>('ALL');
  const [severityFilter, setSeverityFilter] = useState<AuditSeverity | 'ALL'>('ALL');
  const [outcomeFilter, setOutcomeFilter] = useState<AuditOutcome | 'ALL'>('ALL');
  const [dltFilter, setDltFilter] = useState<'ALL' | 'ANCHORED' | 'LOCAL_ONLY'>('ALL');
  const [timeFilter, setTimeFilter] = useState<'ALL' | 'TODAY' | 'LAST_24_HOURS' | 'LAST_7_DAYS' | 'LAST_30_DAYS'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Selected event for detail drawer
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  // Document & Recipient lifecycle viewer
  const [selectedDocId, setSelectedDocId] = useState<string>(documents[0]?.id || '');
  const [docLifecycleEvents, setDocLifecycleEvents] = useState<AuditEvent[]>([]);

  // Load audit records
  const refreshAuditData = async () => {
    setIsLoading(true);
    try {
      const filter: AuditQueryFilter = {
        category: categoryFilter,
        severity: severityFilter,
        outcome: outcomeFilter,
        dltStatus: dltFilter,
        timeRange: timeFilter,
        searchQuery,
      };
      const queried = await auditService.queryEvents(filter);
      // Reverse for newest first in UI display
      setEvents([...queried].reverse());

      const detectedAlerts = await auditService.detectSecurityAlerts();
      setAlerts(detectedAlerts);

      // Evaluate stateful security incidents
      const detectedIncidents = await securityIncidentEngine.evaluateAuditStream();
      setIncidents(detectedIncidents);

      const chain = await auditService.verifyAuditChain();
      setChainResult(chain);

      if (selectedDocId) {
        const docEvents = await auditService.getDocumentLifecycleTimeline(selectedDocId);
        setDocLifecycleEvents(docEvents);
      }
    } catch (e) {
      console.error('[AuditCenter] Failed to load audit records:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    refreshAuditData();
  }, [categoryFilter, severityFilter, outcomeFilter, dltFilter, timeFilter, searchQuery, selectedDocId]);

  const handleVerifyChain = async () => {
    setIsVerifyingChain(true);
    try {
      const res = await auditService.verifyAuditChain();
      setChainResult(res);
    } finally {
      setIsVerifyingChain(false);
    }
  };

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  // Severity badge helper
  const getSeverityBadge = (severity: AuditSeverity) => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 border border-rose-300">CRITICAL</span>;
      case 'ERROR':
        return <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-100 text-amber-800 border border-amber-300">ERROR</span>;
      case 'WARNING':
        return <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-50 text-amber-700 border border-amber-200">WARNING</span>;
      case 'NOTICE':
        return <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-blue-50 text-blue-700 border border-blue-200">NOTICE</span>;
      default:
        return <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono text-slate-600 bg-slate-100 border border-slate-200">INFO</span>;
    }
  };

  // Outcome badge helper
  const getOutcomeBadge = (outcome: AuditOutcome) => {
    switch (outcome) {
      case 'SUCCESS':
        return <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-700"><CheckCircle2 className="w-3 h-3 text-emerald-600" /> SUCCESS</span>;
      case 'DENIED':
        return <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-amber-700"><Lock className="w-3 h-3 text-amber-600" /> DENIED</span>;
      case 'REJECTED':
        return <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-rose-700"><XCircle className="w-3 h-3 text-rose-600" /> REJECTED</span>;
      case 'FAILURE':
        return <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-rose-700"><AlertTriangle className="w-3 h-3 text-rose-600" /> FAILURE</span>;
      default:
        return <span className="text-[11px] text-slate-500 font-medium">PENDING</span>;
    }
  };

  // Event category icon
  const getCategoryIcon = (category: AuditCategory, eventType: string) => {
    if (eventType.includes('DECRYPT')) return <Unlock className="w-4 h-4 text-emerald-600" />;
    if (eventType.includes('WATERMARK')) return <Layers className="w-4 h-4 text-indigo-600" />;
    if (eventType.includes('PACKAGE')) return <Package className="w-4 h-4 text-slate-600" />;
    if (eventType.includes('CERTIFICATE')) return <Award className="w-4 h-4 text-emerald-600" />;
    if (eventType.includes('FORENSIC') || eventType.includes('ATTRIBUTION')) return <Search className="w-4 h-4 text-purple-600" />;
    if (eventType.includes('TAMPER') || eventType.includes('UNAUTHORIZED') || eventType.includes('FORGERY')) return <ShieldAlert className="w-4 h-4 text-rose-600" />;
    if (category === 'LEDGER' || eventType.includes('DLT') || eventType.includes('PROVENANCE')) return <Database className="w-4 h-4 text-blue-600" />;
    return <FileText className="w-4 h-4 text-slate-600" />;
  };

  // Metrics calculation
  const totalEventsCount = events.length;
  const securityEventsCount = events.filter((e) => e.category === 'SECURITY' || e.severity === 'WARNING' || e.severity === 'ERROR' || e.severity === 'CRITICAL').length;
  const criticalCount = events.filter((e) => e.severity === 'CRITICAL').length;
  const dltAnchoredCount = events.filter((e) => e.dltAnchored).length;

  return (
    <PageShell>
      <PageHeader
        title="Security Operations & Audit Center"
        description="Chronological, tamper-evident cryptographic log with hash chaining, anomaly detection, and immutable DLT correlation."
        badge={
          chainResult?.valid ? (
            <VerificationBadge label="Hash Chain: Intact" />
          ) : (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-rose-50 text-rose-700 border border-rose-200">
              <XCircle className="w-3 h-3 text-rose-600" />
              <span>Hash Chain: Tampered</span>
            </span>
          )
        }
      />

      {/* 1. TOP STATISTICAL TILES (Derived strictly from real audit records) */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="p-3.5 bg-white rounded-xl border border-slate-200 shadow-2xs">
          <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">Total Events</span>
          <div className="mt-1 flex items-baseline justify-between">
            <span className="text-xl font-bold font-mono text-slate-900">{totalEventsCount}</span>
            <span className="text-[10px] text-slate-400 font-mono">Recorded</span>
          </div>
        </div>

        <div className="p-3.5 bg-white rounded-xl border border-slate-200 shadow-2xs">
          <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">Security Alerts</span>
          <div className="mt-1 flex items-baseline justify-between">
            <span className={`text-xl font-bold font-mono ${alerts.length > 0 ? 'text-amber-600' : 'text-slate-900'}`}>
              {alerts.length}
            </span>
            <span className="text-[10px] text-slate-400 font-mono">Active</span>
          </div>
        </div>

        <div className="p-3.5 bg-white rounded-xl border border-slate-200 shadow-2xs">
          <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">Critical Incidents</span>
          <div className="mt-1 flex items-baseline justify-between">
            <span className={`text-xl font-bold font-mono ${criticalCount > 0 ? 'text-rose-600' : 'text-slate-900'}`}>
              {criticalCount}
            </span>
            <span className="text-[10px] text-slate-400 font-mono">Priority 1</span>
          </div>
        </div>

        <div className="p-3.5 bg-white rounded-xl border border-slate-200 shadow-2xs">
          <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">DLT Anchored</span>
          <div className="mt-1 flex items-baseline justify-between">
            <span className="text-xl font-bold font-mono text-indigo-600">{dltAnchoredCount}</span>
            <span className="text-[10px] text-slate-400 font-mono">Consensus</span>
          </div>
        </div>

        <div className="p-3.5 bg-white rounded-xl border border-slate-200 shadow-2xs">
          <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">Audit Chain</span>
          <div className="mt-1 flex items-center justify-between">
            <span className={`text-xs font-bold font-mono ${chainResult?.valid ? 'text-emerald-700' : 'text-rose-600'}`}>
              {chainResult?.valid ? '✓ VERIFIED' : '✖ TAMPERED'}
            </span>
            <button
              type="button"
              onClick={handleVerifyChain}
              disabled={isVerifyingChain}
              className="text-[10px] font-semibold text-indigo-600 hover:text-indigo-800 underline cursor-pointer"
            >
              {isVerifyingChain ? 'Verifying...' : 'Verify'}
            </button>
          </div>
        </div>
      </div>

      {/* 2. SUBTABS NAVIGATION */}
      <div className="flex border-b border-slate-200 gap-1 overflow-x-auto">
        <button
          type="button"
          onClick={() => setSubTab('timeline')}
          className={`px-4 py-2 text-xs font-medium border-b-2 -mb-px transition-colors flex items-center gap-1.5 ${
            subTab === 'timeline'
              ? 'border-indigo-600 text-indigo-600 font-semibold'
              : 'border-transparent text-slate-500 hover:text-slate-900'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Activity Timeline</span>
        </button>

        <button
          type="button"
          onClick={() => setSubTab('alerts')}
          className={`px-4 py-2 text-xs font-medium border-b-2 -mb-px transition-colors flex items-center gap-1.5 ${
            subTab === 'alerts'
              ? 'border-indigo-600 text-indigo-600 font-semibold'
              : 'border-transparent text-slate-500 hover:text-slate-900'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Threat & Alert Center</span>
          {alerts.length > 0 && (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-amber-100 text-amber-800 font-mono font-bold">
              {alerts.length}
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => setSubTab('document_lifecycle')}
          className={`px-4 py-2 text-xs font-medium border-b-2 -mb-px transition-colors flex items-center gap-1.5 ${
            subTab === 'document_lifecycle'
              ? 'border-indigo-600 text-indigo-600 font-semibold'
              : 'border-transparent text-slate-500 hover:text-slate-900'
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          <span>Document Lifecycle</span>
        </button>

        <button
          type="button"
          onClick={() => setSubTab('integrity')}
          className={`px-4 py-2 text-xs font-medium border-b-2 -mb-px transition-colors flex items-center gap-1.5 ${
            subTab === 'integrity'
              ? 'border-indigo-600 text-indigo-600 font-semibold'
              : 'border-transparent text-slate-500 hover:text-slate-900'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
          <span>Cryptographic Hash Chain</span>
        </button>
      </div>

      {/* SUBTAB 1: ACTIVITY TIMELINE */}
      {subTab === 'timeline' && (
        <div className="space-y-4">
          {/* Filter Bar & Export Controls */}
          <Section title="Audit Filter & Search" description="Filter chronological event stream across categories, actors, and DLT anchor status.">
            <div className="space-y-3 pt-2">
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                {/* Search Bar */}
                <div className="sm:col-span-2 relative">
                  <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search by eventId, documentId, recipient, or hash..."
                    className="w-full pl-9 pr-3 py-1.5 text-xs font-mono bg-white border border-slate-200 rounded-lg focus:outline-hidden focus:border-indigo-500"
                  />
                </div>

                {/* Category Filter */}
                <div>
                  <select
                    value={categoryFilter}
                    onChange={(e) => setCategoryFilter(e.target.value as any)}
                    className="w-full px-2.5 py-1.5 text-xs bg-white border border-slate-200 rounded-lg text-slate-700"
                  >
                    <option value="ALL">All Categories</option>
                    <option value="SECURITY">Security & Access</option>
                    <option value="DECRYPTION">Decryption</option>
                    <option value="DISTRIBUTION">Distribution</option>
                    <option value="PACKAGE">Package (.sihpkg)</option>
                    <option value="WATERMARK">Forensic Watermark</option>
                    <option value="LEDGER">DLT Ledger</option>
                    <option value="FORENSICS">Forensics</option>
                    <option value="CERTIFICATE">Attribution Certificate</option>
                  </select>
                </div>

                {/* Severity Filter */}
                <div>
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value as any)}
                    className="w-full px-2.5 py-1.5 text-xs bg-white border border-slate-200 rounded-lg text-slate-700"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="INFO">INFO</option>
                    <option value="WARNING">WARNING</option>
                    <option value="ERROR">ERROR</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>
              </div>

              {/* Secondary Filter Line & Export Actions */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-100">
                <div className="flex flex-wrap items-center gap-2">
                  <select
                    value={outcomeFilter}
                    onChange={(e) => setOutcomeFilter(e.target.value as any)}
                    className="px-2 py-1 text-[11px] bg-slate-50 border border-slate-200 rounded text-slate-700"
                  >
                    <option value="ALL">All Outcomes</option>
                    <option value="SUCCESS">SUCCESS</option>
                    <option value="DENIED">DENIED</option>
                    <option value="REJECTED">REJECTED</option>
                    <option value="FAILURE">FAILURE</option>
                  </select>

                  <select
                    value={dltFilter}
                    onChange={(e) => setDltFilter(e.target.value as any)}
                    className="px-2 py-1 text-[11px] bg-slate-50 border border-slate-200 rounded text-slate-700"
                  >
                    <option value="ALL">All Ledger Status</option>
                    <option value="ANCHORED">DLT Anchored Only</option>
                    <option value="LOCAL_ONLY">Local Store Only</option>
                  </select>

                  <select
                    value={timeFilter}
                    onChange={(e) => setTimeFilter(e.target.value as any)}
                    className="px-2 py-1 text-[11px] bg-slate-50 border border-slate-200 rounded text-slate-700"
                  >
                    <option value="ALL">All Time</option>
                    <option value="TODAY">Today</option>
                    <option value="LAST_24_HOURS">Last 24 Hours</option>
                    <option value="LAST_7_DAYS">Last 7 Days</option>
                    <option value="LAST_30_DAYS">Last 30 Days</option>
                  </select>
                </div>

                <div className="flex items-center gap-2">
                  <SecondaryButton
                    size="sm"
                    icon={<Download className="w-3.5 h-3.5" />}
                    onClick={() => auditService.exportAuditJson(events)}
                  >
                    Export JSON
                  </SecondaryButton>
                  <SecondaryButton
                    size="sm"
                    icon={<Download className="w-3.5 h-3.5" />}
                    onClick={() => auditService.exportAuditCsv(events)}
                  >
                    Export CSV
                  </SecondaryButton>
                </div>
              </div>
            </div>
          </Section>

          {/* Timeline Events List */}
          <div className="space-y-2">
            {events.length === 0 ? (
              <div className="p-8 bg-white border border-slate-200 rounded-xl text-center space-y-2">
                <Activity className="w-8 h-8 text-slate-300 mx-auto" />
                <div className="text-xs font-semibold text-slate-700">No matching audit events recorded</div>
                <p className="text-[11px] text-slate-400">
                  Operations across encryption, decryption, and forensic investigation will automatically register in the chronological hash chain.
                </p>
              </div>
            ) : (
              events.map((evt) => (
                <div
                  key={evt.eventId}
                  onClick={() => setSelectedEvent(evt)}
                  className={`p-3.5 bg-white border rounded-xl hover:border-indigo-300 hover:shadow-2xs transition-all cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                    evt.severity === 'CRITICAL'
                      ? 'border-rose-300 bg-rose-50/20'
                      : evt.severity === 'WARNING' || evt.severity === 'ERROR'
                      ? 'border-amber-200 bg-amber-50/10'
                      : 'border-slate-200'
                  }`}
                >
                  {/* Left: Type, Icon & Description */}
                  <div className="flex items-start gap-3 min-w-0">
                    <div className="w-8 h-8 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-center shrink-0 mt-0.5">
                      {getCategoryIcon(evt.category, evt.eventType)}
                    </div>
                    <div className="min-w-0 space-y-0.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs font-bold text-slate-900">
                          {evt.eventType.replace(/_/g, ' ')}
                        </span>
                        {getSeverityBadge(evt.severity)}
                        {getOutcomeBadge(evt.outcome)}
                        {evt.dltAnchored && (
                          <span className="inline-flex items-center gap-1 px-1.5 py-0.2 rounded text-[10px] font-mono bg-indigo-50 text-indigo-700 border border-indigo-200">
                            <Database className="w-2.5 h-2.5" /> Block #{evt.dltBlockHeight || evt.blockIndex || 1}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-700 truncate">{evt.description}</p>
                      <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-slate-400">
                        <span>{new Date(evt.timestampEpochMs).toLocaleTimeString()}</span>
                        {evt.actor.displayName && <span>Actor: {evt.actor.displayName}</span>}
                        {evt.documentId && <span>Doc: {evt.documentId}</span>}
                        {evt.packageId && <span>Pkg: {evt.packageId}</span>}
                      </div>
                    </div>
                  </div>

                  {/* Right: Technical Digest preview & Drawer indicator */}
                  <div className="flex sm:flex-col items-center sm:items-end justify-between shrink-0 text-right">
                    <span className="font-mono text-[10px] text-slate-400">
                      Digest: {evt.eventHash?.slice(0, 10)}...
                    </span>
                    <span className="text-[11px] font-semibold text-indigo-600 hover:text-indigo-800">
                      Inspect event &rarr;
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* SUBTAB 2: THREAT & INCIDENT RESPONSE CENTER */}
      {subTab === 'alerts' && (
        <div className="space-y-4">
          <Section
            title="Stateful Security Incidents & Threat Response"
            description="Continuous correlation engine (NIST CSF 2.0). Distinguishes mathematical cryptographic failures (CERTAIN confidence) from heuristic anomalies. Tracks live incidents through OPEN, ACKNOWLEDGED, INVESTIGATING, and RESOLVED states."
          >
            {/* Incident Status Quick Filter Bar */}
            <div className="flex flex-wrap items-center justify-between gap-2 pt-2 pb-3 border-b border-slate-200">
              <div className="flex items-center gap-1.5 overflow-x-auto">
                <span className="text-[11px] font-semibold text-slate-500 mr-1">Filter Status:</span>
                {(['ALL', 'OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'] as const).map(
                  (st) => (
                    <button
                      key={st}
                      type="button"
                      onClick={() => setIncidentStatusFilter(st)}
                      className={`px-2.5 py-1 text-[11px] font-mono rounded-lg transition-colors cursor-pointer ${
                        incidentStatusFilter === st
                          ? 'bg-indigo-600 text-white font-bold'
                          : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                      }`}
                    >
                      {st} {st !== 'ALL' && `(${incidents.filter((i) => i.status === st).length})`}
                    </button>
                  )
                )}
              </div>

              <div className="text-[11px] font-mono text-slate-400">
                {incidents.length} Incident(s) Recorded
              </div>
            </div>

            <div className="space-y-3 pt-3">
              {incidents.filter((inc) => incidentStatusFilter === 'ALL' || inc.status === incidentStatusFilter).length === 0 ? (
                <div className="p-8 bg-white border border-slate-200 rounded-xl text-center space-y-2">
                  <ShieldCheck className="w-8 h-8 text-emerald-500 mx-auto" />
                  <div className="text-xs font-semibold text-slate-800">
                    No matching security incidents {incidentStatusFilter !== 'ALL' ? `with status "${incidentStatusFilter}"` : 'detected'}
                  </div>
                  <p className="text-[11px] text-slate-400">
                    All cryptographic operations, key envelopes, and validator consensus quorums are operating within baseline parameters.
                  </p>
                </div>
              ) : (
                incidents
                  .filter((inc) => incidentStatusFilter === 'ALL' || inc.status === incidentStatusFilter)
                  .map((inc) => (
                    <div
                      key={inc.incidentId}
                      className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-all hover:shadow-2xs ${
                        inc.severity === 'CRITICAL'
                          ? 'bg-rose-50/70 border-rose-300'
                          : inc.severity === 'HIGH'
                          ? 'bg-amber-50/70 border-amber-300'
                          : 'bg-slate-50 border-slate-200'
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <div className="w-8 h-8 rounded-lg bg-white border border-slate-200 flex items-center justify-center shrink-0 mt-0.5">
                          <Flame className={`w-4 h-4 ${inc.severity === 'CRITICAL' ? 'text-rose-600' : 'text-amber-600'}`} />
                        </div>
                        <div className="space-y-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-xs font-bold font-mono text-slate-900">{inc.title}</span>
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-rose-200 text-rose-900">
                              {inc.severity}
                            </span>
                            <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold ${
                              inc.confidence === 'CERTAIN'
                                ? 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                                : 'bg-indigo-100 text-indigo-800 border border-indigo-200'
                            }`}>
                              {inc.confidence === 'CERTAIN' ? 'CONFIDENCE: PROOF' : `CONFIDENCE: ${inc.confidence}`}
                            </span>
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold bg-slate-200 text-slate-800">
                              STATUS: {inc.status}
                            </span>
                            <span className="text-[10px] text-slate-500 font-mono">
                              {inc.evidenceEventIds.length} Evidence Event(s)
                            </span>
                          </div>
                          <p className="text-xs text-slate-700">{inc.description}</p>
                          <div className="flex flex-wrap items-center gap-3 text-[10px] text-slate-500 font-mono">
                            <span>ID: {inc.incidentId}</span>
                            <span>Rule: {inc.ruleId}</span>
                            <span>First: {new Date(inc.firstObservedAt).toLocaleTimeString()}</span>
                            <span>Last: {new Date(inc.lastObservedAt).toLocaleTimeString()}</span>
                            {inc.affectedRecipientId && <span>Target: {inc.affectedRecipientId}</span>}
                          </div>
                        </div>
                      </div>

                      <div className="shrink-0 flex items-center gap-2">
                        <PrimaryButton
                          size="sm"
                          onClick={() => setSelectedIncident(inc)}
                        >
                          Triage & Respond &rarr;
                        </PrimaryButton>
                      </div>
                    </div>
                  ))
              )}
            </div>
          </Section>
        </div>
      )}

      {/* SUBTAB 3: DOCUMENT LIFECYCLE RECONSTRUCTION */}
      {subTab === 'document_lifecycle' && (
        <div className="space-y-4">
          <Section
            title="Complete Document Lifecycle Reconstruction"
            description="Inspect the full cryptographic chain of custody: Creation &rarr; Encryption &rarr; Distribution &rarr; Export &rarr; Decryption &rarr; Watermark &rarr; Leak &rarr; Attribution."
          >
            <div className="space-y-4 pt-2">
              {/* Document Selector */}
              <div className="flex items-center gap-3">
                <span className="text-xs font-semibold text-slate-700">Select Document:</span>
                <select
                  value={selectedDocId}
                  onChange={(e) => setSelectedDocId(e.target.value)}
                  className="px-3 py-1.5 text-xs bg-white border border-slate-200 rounded-lg text-slate-800 font-medium"
                >
                  {documents.map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.title} ({d.id})
                    </option>
                  ))}
                </select>
              </div>

              {/* Lifecycle Steps Trail */}
              {docLifecycleEvents.length === 0 ? (
                <div className="p-6 bg-slate-50 border border-slate-200 rounded-xl text-center text-xs text-slate-500">
                  No lifecycle events recorded yet for this document.
                </div>
              ) : (
                <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200">
                  {docLifecycleEvents.map((evt, idx) => (
                    <div key={evt.eventId} className="relative group">
                      {/* Node Dot */}
                      <div className="absolute -left-6 top-1 w-5 h-5 rounded-full bg-white border-2 border-indigo-600 flex items-center justify-center">
                        <div className="w-2 h-2 rounded-full bg-indigo-600" />
                      </div>

                      <div className="p-3 bg-white border border-slate-200 rounded-xl shadow-2xs space-y-1">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className="font-mono text-xs font-bold text-slate-900">
                            {idx + 1}. {evt.eventType.replace(/_/g, ' ')}
                          </span>
                          <span className="text-[10px] font-mono text-slate-400">
                            {new Date(evt.timestampEpochMs).toLocaleString()}
                          </span>
                        </div>
                        <p className="text-xs text-slate-700">{evt.description}</p>
                        <div className="flex flex-wrap items-center gap-3 text-[10px] font-mono text-slate-500 pt-1">
                          {evt.actor.displayName && <span>By: {evt.actor.displayName}</span>}
                          {evt.watermarkId && <span>Watermark: {evt.watermarkId}</span>}
                          {evt.dltAnchored && (
                            <span className="text-indigo-600 font-semibold">
                              Ledger Block #{evt.dltBlockHeight || evt.blockIndex}
                            </span>
                          )}
                          {evt.certificateId && (
                            <span className="text-emerald-700 font-semibold">
                              Cert: {evt.certificateId}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Section>
        </div>
      )}

      {/* SUBTAB 4: CRYPTOGRAPHIC HASH CHAIN INTEGRITY */}
      {subTab === 'integrity' && (
        <div className="space-y-4">
          <Section
            title="Tamper-Evident Cryptographic Hash Chain"
            description="Under RFC 8785 and SHA-256 standards, each audit event is sequentially bound to the previous event's digest: H(E_n + H(E_n-1)). Any modification or deletion breaks the chain."
          >
            <div className="space-y-4 pt-2">
              <div className="p-4 rounded-xl border bg-slate-50 border-slate-200 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-emerald-600" />
                    <span className="text-xs font-bold text-slate-900 uppercase tracking-wide">
                      AUDIT LOG INTEGRITY AUDIT STATUS
                    </span>
                  </div>
                  <PrimaryButton size="sm" onClick={handleVerifyChain} disabled={isVerifyingChain}>
                    {isVerifyingChain ? 'Verifying Chain...' : 'Run Cryptographic Audit'}
                  </PrimaryButton>
                </div>

                {chainResult && (
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 border-t border-slate-200">
                    <div className="space-y-0.5">
                      <span className="text-[11px] text-slate-500">Chain Status:</span>
                      <div className={`text-xs font-mono font-bold ${chainResult.valid ? 'text-emerald-700' : 'text-rose-600'}`}>
                        {chainResult.valid ? 'INTEGRITY INTACT (0 VIOLATIONS)' : 'TAMPERING DETECTED'}
                      </div>
                    </div>
                    <div className="space-y-0.5">
                      <span className="text-[11px] text-slate-500">Events Audited:</span>
                      <div className="text-xs font-mono font-bold text-slate-900">
                        {chainResult.eventsChecked} Sequential Events
                      </div>
                    </div>
                    <div className="space-y-0.5">
                      <span className="text-[11px] text-slate-500">Chain Head Digest:</span>
                      <div className="text-xs font-mono text-slate-700 truncate">
                        {chainResult.latestEventHash ? `${chainResult.latestEventHash.slice(0, 20)}...` : 'None'}
                      </div>
                    </div>
                  </div>
                )}

                {chainResult && !chainResult.valid && (
                  <div className="p-3 rounded-lg bg-rose-50 border border-rose-200 text-xs text-rose-800 space-y-1">
                    <div className="font-bold">Tamper Alert: Audit Hash Mismatch Detected</div>
                    <div>Event ID: {chainResult.firstInvalidEvent}</div>
                    <div>Reason: {chainResult.reason}</div>
                  </div>
                )}
              </div>
            </div>
          </Section>
        </div>
      )}

      {/* EVENT DETAIL DRAWER / MODAL */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-2xs flex justify-end animate-in fade-in">
          <div className="w-full max-w-xl bg-white h-full shadow-2xl p-6 overflow-y-auto space-y-6">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200">
              <div className="space-y-0.5">
                <span className="text-xs font-bold text-indigo-600 font-mono">{selectedEvent.eventId}</span>
                <h3 className="text-base font-bold text-slate-900">{selectedEvent.eventType.replace(/_/g, ' ')}</h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedEvent(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-700 cursor-pointer"
              >
                ✕
              </button>
            </div>

            {/* Event Overview */}
            <div className="space-y-2 text-xs">
              <KeyValueRow label="Timestamp (UTC)" value={selectedEvent.timestamp} />
              <KeyValueRow label="Category" value={selectedEvent.category} />
              <KeyValueRow label="Severity" value={selectedEvent.severity} />
              <KeyValueRow label="Outcome" value={selectedEvent.outcome} />
              <KeyValueRow label="Actor" value={`${selectedEvent.actor.displayName || 'System'} (${selectedEvent.actor.type})`} />
              <KeyValueRow label="Resource" value={`${selectedEvent.resource.type}: ${selectedEvent.resource.id || 'N/A'}`} />
              {selectedEvent.documentId && <KeyValueRow label="Document ID" value={selectedEvent.documentId} />}
              {selectedEvent.packageId && <KeyValueRow label="Package ID" value={selectedEvent.packageId} />}
              {selectedEvent.recipientId && <KeyValueRow label="Recipient ID" value={selectedEvent.recipientId} />}
              {selectedEvent.sessionId && <KeyValueRow label="Session ID" value={selectedEvent.sessionId} />}
              {selectedEvent.watermarkId && <KeyValueRow label="Watermark ID" value={selectedEvent.watermarkId} />}
              {selectedEvent.certificateId && <KeyValueRow label="Certificate ID" value={selectedEvent.certificateId} />}
              {selectedEvent.caseId && <KeyValueRow label="Case ID" value={selectedEvent.caseId} />}
            </div>

            {/* Description */}
            <div className="space-y-1">
              <span className="text-xs font-semibold text-slate-700">Description:</span>
              <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 text-xs text-slate-800 font-mono">
                {selectedEvent.description}
              </div>
            </div>

            {/* Cryptographic Hash Chain Proof */}
            <div className="p-4 bg-slate-900 rounded-xl text-white space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between pb-2 border-b border-slate-700">
                <span className="font-bold text-slate-300">CRYPTOGRAPHIC PROOF</span>
                <span className="text-[10px] text-emerald-400">RFC 8785 Canonical SHA-256</span>
              </div>
              <div className="space-y-1">
                <span className="text-[11px] text-slate-400 block">Event Hash:</span>
                <div className="text-[11px] break-all text-emerald-300 font-semibold">{selectedEvent.eventHash || 'Legacy unhashed record'}</div>
              </div>
              <div className="space-y-1">
                <span className="text-[11px] text-slate-400 block">Previous Event Hash:</span>
                <div className="text-[11px] break-all text-slate-300">{selectedEvent.previousEventHash || 'Genesis Anchor'}</div>
              </div>
            </div>

            {/* DLT Provenance Anchor */}
            {selectedEvent.dltAnchored && (
              <div className="p-4 bg-indigo-50 border border-indigo-200 rounded-xl space-y-2 text-xs">
                <div className="flex items-center gap-1.5 font-bold text-indigo-900">
                  <Database className="w-4 h-4 text-indigo-600" />
                  <span>IMMUTABLY ANCHORED ON AIR-GAPPED DLT</span>
                </div>
                <div className="text-indigo-800 text-[11px]">
                  This event is backed by Byzantine Fault Tolerant 3-of-4 validator quorum consensus.
                </div>
                <div className="pt-2 flex gap-2">
                  {onNavigateToLedger && (
                    <SecondaryButton size="sm" onClick={() => { setSelectedEvent(null); onNavigateToLedger(); }}>
                      Inspect in Ledger Explorer
                    </SecondaryButton>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* INCIDENT RESPONSE & TRIAGE DRAWER */}
      {selectedIncident && (
        <IncidentResponseDrawer
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onIncidentUpdated={async () => {
            const updatedIncidents = await securityIncidentEngine.getAllIncidents();
            setIncidents(updatedIncidents);
            if (selectedIncident) {
              const updatedCurrent = updatedIncidents.find((i) => i.incidentId === selectedIncident.incidentId);
              if (updatedCurrent) setSelectedIncident(updatedCurrent);
            }
          }}
          allAuditEvents={events}
          onNavigateToLedger={onNavigateToLedger}
          onNavigateToForensics={onNavigateToForensics}
        />
      )}
    </PageShell>
  );
};
