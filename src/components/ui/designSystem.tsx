import React, { useState } from 'react';
import {
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Copy,
  Check,
  ExternalLink,
  Shield,
  Layers,
} from 'lucide-react';

/* ==========================================================================
   LAYOUT COMPONENTS
   ========================================================================== */

interface PageShellProps {
  children: React.ReactNode;
  className?: string;
}

export const PageShell: React.FC<PageShellProps> = ({ children, className = '' }) => {
  return (
    <div className={`max-w-6xl mx-auto space-y-6 sm:space-y-8 animate-in fade-in duration-150 ${className}`}>
      {children}
    </div>
  );
};

interface PageHeaderProps {
  title: string;
  description: string;
  badge?: React.ReactNode;
  action?: React.ReactNode;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  title,
  description,
  badge,
  action,
}) => {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-200/80">
      <div className="space-y-1">
        <div className="flex items-center gap-2.5">
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900">
            {title}
          </h1>
          {badge}
        </div>
        <p className="text-xs sm:text-sm text-slate-500 max-w-2xl leading-normal">
          {description}
        </p>
      </div>
      {action && <div className="shrink-0 flex items-center gap-2">{action}</div>}
    </div>
  );
};

interface SectionProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  className?: string;
  title?: string;
  description?: string;
  action?: React.ReactNode;
}

export const Section: React.FC<SectionProps> = ({
  children,
  className = '',
  title,
  description,
  action,
  ...props
}) => {
  return (
    <div
      className={`bg-white rounded-xl border border-slate-200/90 shadow-2xs p-4 sm:p-6 transition-all ${className}`}
      {...props}
    >
      {(title || action) && (
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-100">
          <div>
            {title && <h2 className="text-sm font-semibold text-slate-900">{title}</h2>}
            {description && <p className="text-xs text-slate-500 mt-0.5">{description}</p>}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      {children}
    </div>
  );
};

export const Divider: React.FC<{ className?: string }> = ({ className = '' }) => (
  <hr className={`border-slate-100 my-4 ${className}`} />
);

/* ==========================================================================
   BUTTONS
   ========================================================================== */

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
  icon?: React.ReactNode;
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
}

export const PrimaryButton: React.FC<ButtonProps> = ({
  children,
  icon,
  size = 'md',
  loading,
  className = '',
  disabled,
  ...props
}) => {
  const sizeClasses = {
    sm: 'text-xs px-3 py-1.5 gap-1.5 rounded-lg font-medium',
    md: 'text-xs sm:text-sm px-4 py-2 gap-2 rounded-lg font-medium',
    lg: 'text-sm px-5 py-2.5 gap-2.5 rounded-xl font-semibold',
  };

  return (
    <button
      className={`inline-flex items-center justify-center bg-indigo-600 hover:bg-indigo-700 text-white shadow-2xs select-none transition-all active:scale-[0.99] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500/30 ${sizeClasses[size]} ${className}`}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? (
        <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
      ) : (
        icon
      )}
      <span>{children}</span>
    </button>
  );
};

export const SecondaryButton: React.FC<ButtonProps> = ({
  children,
  icon,
  size = 'md',
  loading,
  className = '',
  disabled,
  ...props
}) => {
  const sizeClasses = {
    sm: 'text-xs px-2.5 py-1.5 gap-1.5 rounded-lg font-medium',
    md: 'text-xs sm:text-sm px-3.5 py-2 gap-2 rounded-lg font-medium',
    lg: 'text-sm px-4 py-2.5 gap-2 rounded-xl font-semibold',
  };

  return (
    <button
      className={`inline-flex items-center justify-center bg-white hover:bg-slate-50 text-slate-700 border border-slate-200/90 shadow-2xs select-none transition-all active:scale-[0.99] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500/20 ${sizeClasses[size]} ${className}`}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? (
        <div className="w-3.5 h-3.5 border-2 border-slate-300 border-t-slate-700 rounded-full animate-spin" />
      ) : (
        icon
      )}
      <span>{children}</span>
    </button>
  );
};

export const DangerButton: React.FC<ButtonProps> = ({
  children,
  icon,
  size = 'md',
  loading,
  className = '',
  disabled,
  ...props
}) => {
  const sizeClasses = {
    sm: 'text-xs px-2.5 py-1.5 gap-1.5 rounded-lg font-medium',
    md: 'text-xs sm:text-sm px-3.5 py-2 gap-2 rounded-lg font-medium',
    lg: 'text-sm px-4 py-2.5 gap-2 rounded-xl font-semibold',
  };

  return (
    <button
      className={`inline-flex items-center justify-center bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 select-none transition-all active:scale-[0.99] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/20 ${sizeClasses[size]} ${className}`}
      disabled={disabled || loading}
      {...props}
    >
      {icon}
      <span>{children}</span>
    </button>
  );
};

export const TextButton: React.FC<ButtonProps> = ({
  children,
  icon,
  className = '',
  ...props
}) => {
  return (
    <button
      className={`inline-flex items-center gap-1.5 text-xs font-medium text-slate-500 hover:text-slate-900 transition-colors cursor-pointer select-none ${className}`}
      {...props}
    >
      {icon}
      <span>{children}</span>
    </button>
  );
};

/* ==========================================================================
   STATUS & BADGES
   ========================================================================== */

export type StatusVariant = 'verified' | 'pending' | 'failed' | 'neutral' | 'active';

interface StatusBadgeProps {
  status: StatusVariant;
  children: React.ReactNode;
  icon?: React.ReactNode;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  children,
  icon,
  className = '',
}) => {
  const variantStyles: Record<StatusVariant, string> = {
    verified: 'bg-emerald-50 text-emerald-800 border-emerald-200/80',
    active: 'bg-emerald-50 text-emerald-800 border-emerald-200/80',
    pending: 'bg-amber-50 text-amber-800 border-amber-200/80',
    failed: 'bg-rose-50 text-rose-800 border-rose-200/80',
    neutral: 'bg-slate-100 text-slate-700 border-slate-200',
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-medium border ${variantStyles[status]} ${className}`}
    >
      {icon}
      {children}
    </span>
  );
};

export const VerificationBadge: React.FC<{ label?: string }> = ({ label = 'Verified' }) => (
  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200/90">
    <CheckCircle2 className="w-3 h-3 text-emerald-600" />
    <span>{label}</span>
  </span>
);

/* ==========================================================================
   PROGRESSIVE DISCLOSURE (TECHNICAL DETAILS)
   ========================================================================== */

interface TechnicalDetailsProps {
  title?: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
  className?: string;
}

export const TechnicalDetails: React.FC<TechnicalDetailsProps> = ({
  title = 'View technical details',
  children,
  defaultOpen = false,
  className = '',
}) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div className={`border border-slate-200/80 rounded-xl overflow-hidden bg-slate-50/60 ${className}`}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-4 py-2.5 flex items-center justify-between text-xs font-medium text-slate-600 hover:text-slate-900 transition-colors select-none cursor-pointer"
      >
        <span className="flex items-center gap-2 font-mono text-[11px] text-slate-500">
          <Layers className="w-3.5 h-3.5 text-slate-400" />
          <span>{title}</span>
        </span>
        {isOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
      </button>

      {isOpen && (
        <div className="p-4 pt-2 border-t border-slate-200/80 bg-white space-y-3 font-mono text-xs">
          {children}
        </div>
      )}
    </div>
  );
};

interface KeyValueRowProps {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  copyable?: boolean;
}

export const KeyValueRow: React.FC<KeyValueRowProps> = ({
  label,
  value,
  mono = true,
  copyable = false,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (typeof value === 'string') {
      navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 py-1.5 border-b border-slate-100 last:border-b-0 text-xs">
      <span className="text-slate-500">{label}</span>
      <div className="flex items-center gap-1.5 text-slate-900">
        <span className={mono ? 'font-mono text-[11px] break-all' : 'font-medium'}>
          {value}
        </span>
        {copyable && typeof value === 'string' && (
          <button
            onClick={handleCopy}
            title="Copy value"
            className="p-1 text-slate-400 hover:text-slate-700 rounded transition-colors cursor-pointer"
          >
            {copied ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
          </button>
        )}
      </div>
    </div>
  );
};

export const HashDisplay: React.FC<{ hash: string; label?: string }> = ({ hash, label }) => {
  const [copied, setCopied] = useState(false);
  const truncated = `${hash.slice(0, 8)}••••${hash.slice(-8)}`;

  const handleCopy = () => {
    navigator.clipboard.writeText(hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-100 border border-slate-200/90 text-slate-700 font-mono text-[11px]">
      {label && <span className="text-slate-400 mr-1">{label}:</span>}
      <span>{truncated}</span>
      <button
        onClick={handleCopy}
        title="Copy full hash"
        className="p-0.5 text-slate-400 hover:text-slate-700 transition-colors cursor-pointer"
      >
        {copied ? <Check className="w-2.5 h-2.5 text-emerald-600" /> : <Copy className="w-2.5 h-2.5" />}
      </button>
    </div>
  );
};

/* ==========================================================================
   WORKFLOW STATES
   ========================================================================== */

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description: string;
  action?: React.ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  action,
}) => {
  return (
    <div className="p-8 sm:p-12 text-center rounded-xl border border-dashed border-slate-200 bg-slate-50/50 flex flex-col items-center justify-center space-y-3">
      {icon && <div className="text-slate-400 mb-1">{icon}</div>}
      <h3 className="text-sm font-semibold text-slate-900">{title}</h3>
      <p className="text-xs text-slate-500 max-w-sm">{description}</p>
      {action && <div className="pt-2">{action}</div>}
    </div>
  );
};

export const LoadingState: React.FC<{ message?: string }> = ({
  message = 'Loading cryptographic state...',
}) => {
  return (
    <div className="p-12 text-center flex flex-col items-center justify-center space-y-3">
      <div className="w-6 h-6 border-2 border-slate-200 border-t-indigo-600 rounded-full animate-spin" />
      <p className="text-xs text-slate-500 font-medium">{message}</p>
    </div>
  );
};
