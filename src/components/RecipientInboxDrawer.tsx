import React, { useState, useEffect, useCallback } from 'react';
import {
  X,
  Bell,
  CheckCircle2,
  Clock,
  FileText,
  AlertTriangle,
  ArrowRight,
  ShieldAlert,
  CheckCheck,
  ChevronRight,
  RefreshCw,
  Lock,
} from 'lucide-react';
import {
  PrimaryButton,
  SecondaryButton,
  StatusBadge,
  VerificationBadge,
  KeyValueRow,
  EmptyState,
} from './ui/designSystem';
import { RecipientNotification, DocumentAssignment, NotificationType } from '../types';
import { AssignmentService } from '../services/assignmentService';
import { AuthenticatedSession } from '../crypto/sessionManager';

interface RecipientInboxDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  activeSession: AuthenticatedSession | null;
  onSelectPackage: (packageId: string) => void;
  onUnreadCountChange?: (count: number) => void;
}

export const RecipientInboxDrawer: React.FC<RecipientInboxDrawerProps> = ({
  isOpen,
  onClose,
  activeSession,
  onSelectPackage,
  onUnreadCountChange,
}) => {
  const [notifications, setNotifications] = useState<RecipientNotification[]>([]);
  const [assignments, setAssignments] = useState<Record<string, DocumentAssignment>>({});
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedNotification, setSelectedNotification] = useState<RecipientNotification | null>(null);
  const [filter, setFilter] = useState<'all' | 'unread'>('all');

  const loadData = useCallback(async () => {
    if (!activeSession || activeSession.status !== 'ACTIVE') {
      setNotifications([]);
      setAssignments({});
      if (onUnreadCountChange) onUnreadCountChange(0);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Strictly query for active session recipient only
      const [notifs, asgns] = await Promise.all([
        AssignmentService.getNotificationsForRecipient(activeSession.userId, activeSession),
        AssignmentService.getAssignmentsForRecipient(activeSession.userId, activeSession),
      ]);

      setNotifications(notifs);

      const asgnMap: Record<string, DocumentAssignment> = {};
      for (const asgn of asgns) {
        asgnMap[asgn.assignmentId] = asgn;
        if (asgn.packageId) {
          asgnMap[asgn.packageId] = asgn;
        }
      }
      setAssignments(asgnMap);

      const unreadCount = notifs.filter((n) => !n.read).length;
      if (onUnreadCountChange) {
        onUnreadCountChange(unreadCount);
      }
    } catch (err: any) {
      console.error('[RecipientInboxDrawer] Failed to load notifications:', err);
      setError(err.message || 'Failed to retrieve recipient notifications.');
    } finally {
      setLoading(false);
    }
  }, [activeSession, onUnreadCountChange]);

  useEffect(() => {
    if (isOpen && activeSession) {
      loadData();
    }
  }, [isOpen, activeSession, loadData]);

  // Periodic poll or initial count fetch on mount
  useEffect(() => {
    if (activeSession) {
      AssignmentService.getNotificationsForRecipient(activeSession.userId, activeSession)
        .then((notifs) => {
          const unread = notifs.filter((n) => !n.read).length;
          if (onUnreadCountChange) onUnreadCountChange(unread);
        })
        .catch(() => {});
    }
  }, [activeSession, onUnreadCountChange]);

  const handleMarkAsRead = async (notification: RecipientNotification) => {
    if (!activeSession) return;
    try {
      await AssignmentService.markNotificationRead(notification.notificationId, activeSession.userId, activeSession);
      setNotifications((prev) =>
        prev.map((n) =>
          n.notificationId === notification.notificationId ? { ...n, read: true, readAt: Date.now() } : n
        )
      );
      if (selectedNotification?.notificationId === notification.notificationId) {
        setSelectedNotification((prev) => (prev ? { ...prev, read: true, readAt: Date.now() } : null));
      }
      if (onUnreadCountChange) {
        const remainingUnread = notifications.filter((n) => n.notificationId !== notification.notificationId && !n.read).length;
        onUnreadCountChange(remainingUnread);
      }
    } catch (err) {
      console.warn('Failed to mark notification read:', err);
    }
  };

  const handleMarkAllAsRead = async () => {
    if (!activeSession) return;
    try {
      await AssignmentService.markAllNotificationsRead(activeSession.userId, activeSession);
      const now = Date.now();
      setNotifications((prev) => prev.map((n) => ({ ...n, read: true, readAt: now })));
      if (selectedNotification) {
        setSelectedNotification((prev) => (prev ? { ...prev, read: true, readAt: now } : null));
      }
      if (onUnreadCountChange) onUnreadCountChange(0);
    } catch (err) {
      console.warn('Failed to mark all notifications read:', err);
    }
  };

  const handleOpenDecryption = (notification: RecipientNotification) => {
    if (!notification.packageId) return;
    const assignment = assignments[notification.assignmentId] || (notification.packageId ? assignments[notification.packageId] : undefined);
    if (assignment?.status === 'REVOKED') return;

    onSelectPackage(notification.packageId);
    handleMarkAsRead(notification);
    onClose();
  };

  if (!isOpen) return null;

  const filteredNotifications = notifications.filter((n) => {
    if (filter === 'unread') return !n.read;
    return true;
  });

  const unreadCount = notifications.filter((n) => !n.read).length;

  const renderTypeBadge = (type: NotificationType) => {
    switch (type) {
      case 'PACKAGE_READY':
        return <StatusBadge status="verified">Package Ready</StatusBadge>;
      case 'ASSIGNMENT_CREATED':
        return <StatusBadge status="active">Assigned</StatusBadge>;
      case 'DOCUMENT_DECRYPTED':
        return <StatusBadge status="neutral">Decrypted</StatusBadge>;
      case 'ACCESS_REVOKED':
        return <StatusBadge status="failed">Access Revoked</StatusBadge>;
      case 'ASSIGNMENT_UPDATED':
      default:
        return <StatusBadge status="neutral">Updated</StatusBadge>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-900/40 backdrop-blur-xs flex justify-end animate-in fade-in duration-150">
      <div className="w-full max-w-lg bg-white h-full shadow-2xl flex flex-col border-l border-slate-200 animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="px-5 py-4 border-b border-slate-200/90 flex items-center justify-between bg-slate-50/70">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-indigo-50 border border-indigo-100 rounded-lg text-indigo-700">
              <Bell className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-semibold text-slate-900">Recipient Inbox</h2>
                {unreadCount > 0 && (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-indigo-600 text-white tabular-nums">
                    {unreadCount} unread
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-500 mt-0.5">
                {activeSession ? `Targeted alerts for ${activeSession.userName}` : 'No active session'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-1">
            <button
              onClick={loadData}
              title="Refresh inbox"
              className="p-1.5 text-slate-400 hover:text-slate-600 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <button
              onClick={onClose}
              title="Close inbox"
              className="p-1.5 text-slate-400 hover:text-slate-600 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Action strip & Filter */}
        <div className="px-5 py-2.5 border-b border-slate-100 bg-white flex items-center justify-between text-xs">
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setFilter('all')}
              className={`px-2.5 py-1 rounded-md text-xs font-medium cursor-pointer transition-colors ${
                filter === 'all'
                  ? 'bg-slate-900 text-white'
                  : 'text-slate-600 hover:bg-slate-100'
              }`}
            >
              All ({notifications.length})
            </button>
            <button
              onClick={() => setFilter('unread')}
              className={`px-2.5 py-1 rounded-md text-xs font-medium cursor-pointer transition-colors ${
                filter === 'unread'
                  ? 'bg-slate-900 text-white'
                  : 'text-slate-600 hover:bg-slate-100'
              }`}
            >
              Unread ({unreadCount})
            </button>
          </div>

          {unreadCount > 0 && (
            <button
              onClick={handleMarkAllAsRead}
              className="inline-flex items-center gap-1 text-[11px] font-medium text-indigo-600 hover:text-indigo-800 transition-colors cursor-pointer"
            >
              <CheckCheck className="w-3.5 h-3.5" />
              <span>Mark all read</span>
            </button>
          )}
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {!activeSession ? (
            <EmptyState
              icon={<Lock className="w-6 h-6 text-slate-400" />}
              title="Keystore locked"
              description="Unlock your local post-quantum keystore to access targeted notifications."
            />
          ) : loading ? (
            <div className="py-12 flex flex-col items-center justify-center text-slate-400 space-y-2">
              <div className="w-6 h-6 border-2 border-indigo-600 border-t-transparent rounded-full animate-spin" />
              <span className="text-xs">Loading recipient notifications...</span>
            </div>
          ) : error ? (
            <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-700 flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-600" />
              <div className="space-y-1">
                <div className="font-semibold">Notification Query Error</div>
                <div>{error}</div>
              </div>
            </div>
          ) : filteredNotifications.length === 0 ? (
            <EmptyState
              icon={<Bell className="w-6 h-6 text-slate-400" />}
              title={filter === 'unread' ? 'No unread notifications' : 'Inbox is empty'}
              description={
                filter === 'unread'
                  ? 'All notifications have been marked as read.'
                  : `No distribution notifications found for ${activeSession.userName}. Distributed packages will appear here.`
              }
            />
          ) : (
            <div className="space-y-2">
              {filteredNotifications.map((notif) => {
                const asgn = assignments[notif.assignmentId] || (notif.packageId ? assignments[notif.packageId] : undefined);
                const isRevoked = asgn?.status === 'REVOKED' || notif.type === 'ACCESS_REVOKED';

                return (
                  <div
                    key={notif.notificationId}
                    onClick={() => {
                      setSelectedNotification(notif);
                      if (!notif.read) handleMarkAsRead(notif);
                    }}
                    className={`p-3.5 rounded-xl border transition-all cursor-pointer relative ${
                      !notif.read
                        ? 'bg-indigo-50/40 border-indigo-200/90 shadow-2xs hover:bg-indigo-50/70'
                        : 'bg-white border-slate-200/80 hover:border-slate-300 hover:bg-slate-50/50'
                    }`}
                  >
                    {!notif.read && (
                      <span className="absolute top-3.5 right-3.5 w-2 h-2 rounded-full bg-indigo-600 ring-2 ring-indigo-200" />
                    )}

                    <div className="flex items-center gap-2 mb-1.5">
                      {renderTypeBadge(notif.type)}
                      <span className="text-[10px] text-slate-400 flex items-center gap-1">
                        <Clock className="w-2.5 h-2.5" />
                        {new Date(notif.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} &bull; {new Date(notif.timestamp).toLocaleDateString()}
                      </span>
                    </div>

                    <h4 className="text-xs font-semibold text-slate-900 pr-5">
                      {notif.title}
                    </h4>

                    <p className="text-[11px] text-slate-600 mt-1 line-clamp-2 leading-relaxed">
                      {notif.message}
                    </p>

                    {/* Metadata strip */}
                    <div className="mt-2.5 pt-2 border-t border-slate-100 flex items-center justify-between text-[10px] text-slate-500">
                      <div className="flex items-center gap-1.5 font-mono">
                        <FileText className="w-3 h-3 text-slate-400" />
                        <span className="font-semibold text-slate-700">{notif.documentTitle || 'Document'}</span>
                        {notif.classification && (
                          <span className="px-1.5 py-0.2 bg-slate-100 text-slate-600 rounded text-[9px]">
                            {notif.classification}
                          </span>
                        )}
                      </div>

                      {isRevoked ? (
                        <span className="text-rose-600 font-semibold flex items-center gap-1">
                          <ShieldAlert className="w-3 h-3" />
                          Revoked
                        </span>
                      ) : notif.packageId ? (
                        <span className="text-indigo-600 font-medium flex items-center gap-0.5 hover:underline">
                          Decrypt <ChevronRight className="w-3 h-3" />
                        </span>
                      ) : null}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Selected Notification Detail Overlay / Drawer View */}
        {selectedNotification && (
          <div className="p-4 border-t border-slate-200 bg-slate-50/80 space-y-3">
            <div className="flex items-start justify-between gap-2">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  {renderTypeBadge(selectedNotification.type)}
                  <span className="text-[10px] text-slate-500">
                    {new Date(selectedNotification.timestamp).toLocaleString()}
                  </span>
                </div>
                <h3 className="text-xs font-bold text-slate-900 mt-1">
                  {selectedNotification.title}
                </h3>
              </div>
              <button
                onClick={() => setSelectedNotification(null)}
                className="text-slate-400 hover:text-slate-600 p-1 rounded-md"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            <p className="text-xs text-slate-700 leading-relaxed bg-white p-3 rounded-lg border border-slate-200/80">
              {selectedNotification.message}
            </p>

            {/* Assignment Status Notice */}
            {(() => {
              const asgn = assignments[selectedNotification.assignmentId] || (selectedNotification.packageId ? assignments[selectedNotification.packageId] : undefined);
              if (asgn?.status === 'REVOKED' || selectedNotification.type === 'ACCESS_REVOKED') {
                return (
                  <div className="p-2.5 bg-rose-50 border border-rose-200 rounded-lg text-xs text-rose-800 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0" />
                    <span>
                      <strong>Unavailable:</strong> This document assignment was revoked ({asgn?.revocationReason || 'Revoked by authority'}). Decryption is forbidden.
                    </span>
                  </div>
                );
              }
              return null;
            })()}

            {/* Contextual Action Button */}
            {selectedNotification.packageId && (
              <div className="flex items-center justify-between pt-1">
                <span className="text-[10px] text-slate-400 font-mono">
                  Pkg: {selectedNotification.packageId}
                </span>

                {(() => {
                  const asgn = assignments[selectedNotification.assignmentId] || (selectedNotification.packageId ? assignments[selectedNotification.packageId] : undefined);
                  const isRevoked = asgn?.status === 'REVOKED' || selectedNotification.type === 'ACCESS_REVOKED';

                  return (
                    <PrimaryButton
                      size="sm"
                      disabled={isRevoked}
                      icon={<ArrowRight className="w-3.5 h-3.5" />}
                      onClick={() => handleOpenDecryption(selectedNotification)}
                    >
                      {isRevoked ? 'Package Revoked' : 'Open in Decrypt View'}
                    </PrimaryButton>
                  );
                })()}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
