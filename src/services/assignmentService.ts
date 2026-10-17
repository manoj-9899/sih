/**
 * AEGIS-PQC Document Assignment & Notification Service.
 * 
 * Enforces:
 * 1. Recipient-targeted distribution tracking & lifecycle state transitions.
 * 2. Strict recipient isolation: Recipients only access their own assignments & notifications.
 * 3. Idempotent distribution & package binding: Duplicate calls do not duplicate records.
 * 4. Offline persistence in IndexedDB v2 (with localStorage fallback).
 */

import {
  DocumentAssignment,
  RecipientNotification,
  AssignmentStatus,
  AssignmentOrigin,
  Recipient,
  ClassifiedDocument,
} from '../types';
import { airGappedStorage } from '../storage/airGappedStorage';
import { auditService } from './auditService';

export interface CreateDistributionAssignmentParams {
  doc: ClassifiedDocument | {
    id: string;
    title: string;
    classification: string;
    fileSizeBytes?: number;
    mimeType?: string;
    filename?: string;
  };
  recipients: Recipient[];
  distributionId?: string;
  packageId?: string;
  senderId?: string;
  senderName?: string;
  origin?: AssignmentOrigin;
}

export class AssignmentService {
  /**
   * Generates a deterministic assignment ID based on distributionId and recipientId
   * to guarantee idempotent assignment creation.
   */
  public static computeAssignmentId(distributionId: string, recipientId: string): string {
    return `ASGN-${distributionId}-${recipientId}`;
  }

  /**
   * Creates or idempotently updates assignments and recipient-targeted notifications
   * for each recipient in a distribution event.
   */
  public static async createAssignmentsForDistribution(
    params: CreateDistributionAssignmentParams
  ): Promise<DocumentAssignment[]> {
    const { doc, recipients, senderId = 'SNDR-STRATCOM-01', senderName = 'Directorate of Strategic Operations', origin = 'LOCAL' } = params;
    const distributionId = params.distributionId || `DIST-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 8999 + 1000)}`;
    const packageId = params.packageId;
    const now = Date.now();

    const createdAssignments: DocumentAssignment[] = [];
    const createdNotifications: RecipientNotification[] = [];

    for (const recipient of recipients) {
      const assignmentId = this.computeAssignmentId(distributionId, recipient.id);

      // Check for existing assignment to preserve idempotency
      const existing = await airGappedStorage.getAssignment(assignmentId);

      if (existing) {
        // Idempotency: do not downgrade active/completed lifecycle states
        let updatedStatus = existing.status;
        if (existing.status === 'ASSIGNED' && packageId) {
          updatedStatus = 'PACKAGE_GENERATED';
        }

        const updatedAssignment: DocumentAssignment = {
          ...existing,
          packageId: packageId || existing.packageId,
          packageGeneratedAt: packageId ? (existing.packageGeneratedAt || now) : existing.packageGeneratedAt,
          status: updatedStatus,
          updatedAt: now,
          documentTitle: doc.title,
          classification: doc.classification,
          fileSizeBytes: doc.fileSizeBytes ?? existing.fileSizeBytes,
          filename: doc.filename ?? existing.filename,
        };

        await airGappedStorage.saveAssignment(updatedAssignment);
        createdAssignments.push(updatedAssignment);
      } else {
        // Create new assignment
        const initialStatus: AssignmentStatus = packageId ? 'PACKAGE_GENERATED' : 'ASSIGNED';
        const assignment: DocumentAssignment = {
          assignmentId,
          distributionId,
          packageId,
          documentId: doc.id,
          documentTitle: doc.title,
          classification: doc.classification,
          fileSizeBytes: doc.fileSizeBytes,
          mimeType: doc.mimeType,
          filename: doc.filename,
          senderId,
          senderName,
          recipientId: recipient.id,
          recipientName: recipient.name,
          status: initialStatus,
          origin,
          createdAt: now,
          updatedAt: now,
          packageGeneratedAt: packageId ? now : undefined,
        };

        await airGappedStorage.saveAssignment(assignment);
        createdAssignments.push(assignment);

        // Create targeted notification strictly for this recipient
        const notifId = `NOTIF-${Date.now().toString(36).toUpperCase()}-${recipient.id.replace(/[^a-zA-Z0-9]/g, '')}-${Math.floor(Math.random() * 8999 + 1000)}`;
        const notification: RecipientNotification = {
          notificationId: notifId,
          recipientId: recipient.id,
          assignmentId,
          type: packageId ? 'PACKAGE_READY' : 'ASSIGNMENT_CREATED',
          title: packageId ? 'Secure Package Ready' : 'Document Access Assigned',
          message: packageId
            ? `Encrypted package ready for document "${doc.title}" (${doc.classification}). Ready for local cryptographic decryption.`
            : `You have been authorized access to classified document "${doc.title}" (${doc.classification}).`,
          timestamp: now,
          read: false,
          packageId,
          documentId: doc.id,
          documentTitle: doc.title,
          classification: doc.classification,
          senderId,
          senderName,
        };

        await airGappedStorage.saveNotification(notification);
        createdNotifications.push(notification);
      }
    }

    // Record audit event
    await auditService.record({
      eventType: 'DISTRIBUTION_CREATED',
      severity: 'INFO',
      category: 'DISTRIBUTION',
      actor: { type: 'USER', id: senderId, displayName: senderName },
      resource: { type: 'DISTRIBUTION', id: distributionId },
      action: 'ASSIGN_DOCUMENT',
      outcome: 'SUCCESS',
      description: `Created ${createdAssignments.length} recipient assignments for document "${doc.title}" (${distributionId}).`,
      distributionId,
      packageId,
      metadata: {
        recipients: recipients.map((r) => r.id).join(','),
        recipientCount: recipients.length,
      },
    }).catch((e) => console.warn('[AssignmentService] Audit logging failed:', e));

    return createdAssignments;
  }

  /**
   * Links a generated package ID to all existing assignments in a distribution,
   * transitioning their status to PACKAGE_GENERATED and delivering notifications.
   */
  public static async linkPackageToAssignments(
    distributionId: string,
    packageId: string
  ): Promise<DocumentAssignment[]> {
    const assignments = await airGappedStorage.getAssignmentsByDistribution(distributionId);
    const now = Date.now();
    const updated: DocumentAssignment[] = [];

    for (const asgn of assignments) {
      if (asgn.status === 'ASSIGNED') {
        asgn.status = 'PACKAGE_GENERATED';
        asgn.packageGeneratedAt = now;
      }
      asgn.packageId = packageId;
      asgn.updatedAt = now;
      await airGappedStorage.saveAssignment(asgn);
      updated.push(asgn);

      // Create notification
      const notifId = `NOTIF-PKG-${Date.now().toString(36).toUpperCase()}-${asgn.recipientId.replace(/[^a-zA-Z0-9]/g, '')}-${Math.floor(Math.random() * 8999 + 1000)}`;
      const notif: RecipientNotification = {
        notificationId: notifId,
        recipientId: asgn.recipientId,
        assignmentId: asgn.assignmentId,
        type: 'PACKAGE_READY',
        title: 'Encrypted Package Generated',
        message: `Package ${packageId} for document "${asgn.documentTitle}" is now prepared and ready for decryption.`,
        timestamp: now,
        read: false,
        packageId,
        documentId: asgn.documentId,
        documentTitle: asgn.documentTitle,
        classification: asgn.classification,
        senderId: asgn.senderId,
        senderName: asgn.senderName,
      };
      await airGappedStorage.saveNotification(notif);
    }

    return updated;
  }

  /**
   * Records that a recipient has decrypted their document assignment.
   * Transitions status to DECRYPTED and binds provenance ledger references.
   */
  public static async recordDecryption(
    packageId: string,
    recipientId: string,
    eventId?: string,
    blockHeight?: number
  ): Promise<DocumentAssignment | null> {
    const packageAssignments = await airGappedStorage.getAssignmentsByPackage(packageId);
    const assignment = packageAssignments.find((a) => a.recipientId === recipientId);

    if (!assignment) {
      return null;
    }

    const now = Date.now();
    const updated: DocumentAssignment = {
      ...assignment,
      status: 'DECRYPTED',
      decryptedAt: now,
      updatedAt: now,
      decryptionEventId: eventId || assignment.decryptionEventId,
      decryptionBlockHeight: typeof blockHeight === 'number' ? blockHeight : assignment.decryptionBlockHeight,
    };

    await airGappedStorage.saveAssignment(updated);

    // Targeted notification for recipient confirming decryption provenance
    const notifId = `NOTIF-DEC-${Date.now().toString(36).toUpperCase()}-${recipientId.replace(/[^a-zA-Z0-9]/g, '')}-${Math.floor(Math.random() * 8999 + 1000)}`;
    const notif: RecipientNotification = {
      notificationId: notifId,
      recipientId,
      assignmentId: assignment.assignmentId,
      type: 'DOCUMENT_DECRYPTED',
      title: 'Decryption Recorded in Provenance Ledger',
      message: `Document "${assignment.documentTitle}" was decrypted successfully. Forensic watermark applied and committed${typeof blockHeight === 'number' ? ` in Block #${blockHeight}` : ''}.`,
      timestamp: now,
      read: false,
      packageId,
      documentId: assignment.documentId,
      documentTitle: assignment.documentTitle,
      classification: assignment.classification,
      metadata: {
        eventId,
        blockHeight,
      },
    };
    await airGappedStorage.saveNotification(notif);

    return updated;
  }

  /**
   * Records that a recipient has downloaded their assigned package.
   */
  public static async recordDownload(
    packageId: string,
    recipientId: string
  ): Promise<DocumentAssignment | null> {
    const packageAssignments = await airGappedStorage.getAssignmentsByPackage(packageId);
    const assignment = packageAssignments.find((a) => a.recipientId === recipientId);

    if (!assignment) {
      return null;
    }

    // Do not downgrade if already decrypted
    if (assignment.status === 'DECRYPTED') {
      return assignment;
    }

    const now = Date.now();
    const updated: DocumentAssignment = {
      ...assignment,
      status: 'DOWNLOADED',
      downloadedAt: now,
      updatedAt: now,
    };

    await airGappedStorage.saveAssignment(updated);
    return updated;
  }

  /**
   * Revokes an assignment for a given recipient.
   */
  public static async revokeAssignment(
    assignmentId: string,
    reason = 'Clearance revoked by authority'
  ): Promise<DocumentAssignment | null> {
    const assignment = await airGappedStorage.getAssignment(assignmentId);
    if (!assignment) {
      return null;
    }

    const now = Date.now();
    const updated: DocumentAssignment = {
      ...assignment,
      status: 'REVOKED',
      revokedAt: now,
      updatedAt: now,
      revocationReason: reason,
    };

    await airGappedStorage.saveAssignment(updated);

    // Targeted notification strictly to revoked recipient
    const notifId = `NOTIF-REV-${Date.now().toString(36).toUpperCase()}-${assignment.recipientId.replace(/[^a-zA-Z0-9]/g, '')}-${Math.floor(Math.random() * 8999 + 1000)}`;
    const notif: RecipientNotification = {
      notificationId: notifId,
      recipientId: assignment.recipientId,
      assignmentId: assignment.assignmentId,
      type: 'ACCESS_REVOKED',
      title: 'Document Access Revoked',
      message: `Your access to document "${assignment.documentTitle}" has been revoked: ${reason}.`,
      timestamp: now,
      read: false,
      packageId: assignment.packageId,
      documentId: assignment.documentId,
      documentTitle: assignment.documentTitle,
      classification: assignment.classification,
      metadata: { reason },
    };
    await airGappedStorage.saveNotification(notif);

    return updated;
  }

  // =========================================================================
  // --- RECIPIENT ISOLATION QUERIES ---
  // =========================================================================

  /**
   * Returns assignments strictly belonging to the authorized recipient.
   * Alice cannot access Bob's assignments.
   */
  public static async getAssignmentsForRecipient(recipientId: string): Promise<DocumentAssignment[]> {
    if (!recipientId) return [];
    return await airGappedStorage.getAssignmentsByRecipient(recipientId);
  }

  /**
   * Returns notifications strictly belonging to the authorized recipient.
   * Alice cannot access Bob's notifications.
   */
  public static async getNotificationsForRecipient(recipientId: string): Promise<RecipientNotification[]> {
    if (!recipientId) return [];
    return await airGappedStorage.getNotificationsByRecipient(recipientId);
  }

  /**
   * Marks a notification as read, enforcing that the requesting recipient owns it.
   */
  public static async markNotificationRead(
    notificationId: string,
    recipientId: string
  ): Promise<RecipientNotification | null> {
    return await airGappedStorage.markNotificationAsRead(notificationId, recipientId);
  }

  /**
   * Marks all notifications as read for a given recipient.
   */
  public static async markAllNotificationsRead(recipientId: string): Promise<void> {
    if (!recipientId) return;
    await airGappedStorage.markAllNotificationsAsRead(recipientId);
  }
}
