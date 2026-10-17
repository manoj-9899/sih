/**
 * AEGIS-PQC Document Assignment & Recipient Notification Data Models.
 * Provides attribution, lifecycle tracking, and recipient-isolated alerts
 * in an air-gapped cryptographic document distribution workflow.
 */

export type AssignmentStatus =
  | 'ASSIGNED'
  | 'PACKAGE_GENERATED'
  | 'DOWNLOADED'
  | 'DECRYPTED'
  | 'REVOKED';

export type AssignmentOrigin = 'LOCAL' | 'IMPORTED';

export interface DocumentAssignment {
  /** Unique identifier for this assignment (e.g., ASGN-<distId>-<recipId>) */
  assignmentId: string;
  /** Identifies the parent distribution event */
  distributionId: string;
  /** Cryptographic package ID once generated (.sihpkg) */
  packageId?: string;
  /** Source document reference */
  documentId: string;
  /** Document title for display */
  documentTitle: string;
  /** Classification marking (e.g., TOP SECRET // SCI) */
  classification: string;
  /** Original document size in bytes */
  fileSizeBytes?: number;
  /** Document MIME type */
  mimeType?: string;
  /** Clean document filename */
  filename?: string;
  /** Sender identifier */
  senderId: string;
  /** Sender display name */
  senderName?: string;
  /** Authorized recipient identifier */
  recipientId: string;
  /** Authorized recipient display name */
  recipientName?: string;
  /** Current lifecycle status */
  status: AssignmentStatus;
  /** Origin of the assignment (created locally by sender or imported via package) */
  origin: AssignmentOrigin;
  /** Timestamp when assignment was created */
  createdAt: number;
  /** Timestamp of last status change */
  updatedAt: number;
  /** Optional lifecycle milestone timestamps */
  packageGeneratedAt?: number;
  downloadedAt?: number;
  decryptedAt?: number;
  revokedAt?: number;
  /** Provenance ledger cross-reference if decrypted */
  decryptionEventId?: string;
  decryptionBlockHeight?: number;
  /** Revocation reason if status is REVOKED */
  revocationReason?: string;
  /** Safe non-sensitive metadata */
  metadata?: Record<string, string | number | boolean | null | undefined>;
}

export type NotificationType =
  | 'ASSIGNMENT_CREATED'
  | 'PACKAGE_READY'
  | 'ASSIGNMENT_UPDATED'
  | 'ACCESS_REVOKED'
  | 'DOCUMENT_DECRYPTED';

export interface RecipientNotification {
  /** Unique notification ID */
  notificationId: string;
  /** Targeted recipient ID (strictly isolated) */
  recipientId: string;
  /** Reference to related DocumentAssignment */
  assignmentId: string;
  /** Event classification */
  type: NotificationType;
  /** Short summary title */
  title: string;
  /** Human-readable descriptive text */
  message: string;
  /** Creation timestamp in milliseconds */
  timestamp: number;
  /** Read status */
  read: boolean;
  /** Timestamp when recipient marked notification as read */
  readAt?: number;
  /** Optional linked package reference */
  packageId?: string;
  /** Optional linked document reference */
  documentId?: string;
  documentTitle?: string;
  classification?: string;
  senderId?: string;
  senderName?: string;
  /** Additional structured metadata */
  metadata?: Record<string, string | number | boolean | null | undefined>;
}
