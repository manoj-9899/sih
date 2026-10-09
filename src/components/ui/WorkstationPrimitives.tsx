import React from 'react';

/**
 * Modern High-Tech Light Workstation UI Primitives
 * Refined Swiss & Cryptographic Laboratory Aesthetic
 */

// 1. SURFACES & CONTAINERS
interface SurfaceProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'primary' | 'elevated' | 'recessed';
  children: React.ReactNode;
  className?: string;
}

export const WorkstationSurface: React.FC<SurfaceProps> = ({
  variant = 'primary',
  children,
  className = '',
  ...props
}) => {
  const variantStyles = {
    primary: 'bg-white border border-slate-200/90 shadow-2xs',
    elevated: 'bg-white border border-slate-200 shadow-sm',
    recessed: 'bg-slate-50/80 border border-slate-200/70',
  };

  return (
    <div
      className={`rounded-xl p-5 ${variantStyles[variant]} ${className}`}
      {...props}
    >
      {children}
    </div>
  );
};

// 2. REFINED WORKSTATION BUTTONS
interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'operational' | 'secondary' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  icon?: React.ReactNode;
  children: React.ReactNode;
}

export const OperationalButton: React.FC<ButtonProps> = ({
  variant = 'operational',
  size = 'md',
  icon,
  children,
  className = '',
  disabled,
  ...props
}) => {
  const base =
    'inline-flex items-center justify-center font-medium transition-all select-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500/30 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer';

  const sizes = {
    sm: 'text-xs px-2.5 py-1.5 gap-1.5 rounded-md font-mono',
    md: 'text-xs px-3.5 py-2 gap-2 rounded-lg font-medium',
    lg: 'text-sm px-4 py-2.5 gap-2.5 rounded-lg font-semibold tracking-wide',
  };

  const variants = {
    // Primary Indigo Action
    operational:
      'bg-indigo-600 hover:bg-indigo-700 text-white shadow-xs hover:shadow active:scale-[0.99] border border-indigo-700/20',
    // Secondary Clean White Trigger with subtle border
    secondary:
      'bg-white hover:bg-slate-50 text-slate-700 hover:text-slate-900 border border-slate-200 shadow-2xs hover:border-slate-300',
    // Clinical Danger Trigger (tampering / breach)
    danger:
      'bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 hover:border-rose-300',
    // Minimalist Ghost
    ghost:
      'bg-transparent hover:bg-slate-100 text-slate-600 hover:text-slate-900 border border-transparent',
  };

  return (
    <button
      className={`${base} ${sizes[size]} ${variants[variant]} ${className}`}
      disabled={disabled}
      {...props}
    >
      {icon && <span className="shrink-0">{icon}</span>}
      <span>{children}</span>
    </button>
  );
};

// 3. CLEAN METADATA CHIPS (NO GARISH PILLS)
interface StatusBadgeProps {
  status?: 'nominal' | 'active' | 'inspection' | 'breach' | 'neutral';
  children: React.ReactNode;
  icon?: React.ReactNode;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status = 'neutral',
  children,
  icon,
  className = '',
}) => {
  const statusStyles = {
    nominal: 'text-emerald-700 bg-emerald-50/80 border-emerald-200/80',
    active: 'text-indigo-700 bg-indigo-50/80 border-indigo-200/80',
    inspection: 'text-sky-700 bg-sky-50/80 border-sky-200/80',
    breach: 'text-rose-700 bg-rose-50/80 border-rose-200/80',
    neutral: 'text-slate-600 bg-slate-100/90 border-slate-200/80',
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-mono border font-medium ${statusStyles[status]} ${className}`}
    >
      {icon && <span className="shrink-0">{icon}</span>}
      <span>{children}</span>
    </span>
  );
};

// 4. TABULAR DATA & CRYPTO BLOCKS
interface CryptoDataBlockProps {
  label: string;
  value: string;
  subtext?: string;
  action?: React.ReactNode;
  truncate?: boolean;
}

export const CryptoDataBlock: React.FC<CryptoDataBlockProps> = ({
  label,
  value,
  subtext,
  action,
  truncate = false,
}) => {
  return (
    <div className="bg-slate-50 border border-slate-200 rounded-lg p-2.5 font-mono text-xs">
      <div className="flex items-center justify-between gap-2 mb-1">
        <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider">
          {label}
        </span>
        {action && <div>{action}</div>}
      </div>
      <div
        className={`text-slate-800 break-all select-all font-mono ${
          truncate ? 'truncate' : ''
        }`}
      >
        {value}
      </div>
      {subtext && (
        <div className="text-[10px] text-slate-400 mt-1 font-sans font-normal">
          {subtext}
        </div>
      )}
    </div>
  );
};

// 5. HIGH-DENSITY METRIC TILES
interface MetricTileProps {
  label: string;
  value: string | number;
  subValue?: string;
  status?: 'nominal' | 'active' | 'neutral' | 'breach';
  icon?: React.ReactNode;
}

export const TechnicalMetricTile: React.FC<MetricTileProps> = ({
  label,
  value,
  subValue,
  status = 'neutral',
  icon,
}) => {
  const statusDecorators = {
    nominal: 'text-emerald-600',
    active: 'text-indigo-600',
    neutral: 'text-slate-700',
    breach: 'text-rose-600',
  };

  return (
    <div className="bg-white border border-slate-200/90 rounded-xl p-4 shadow-2xs hover:border-slate-300 transition-all">
      <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
        <span className="font-medium text-slate-500 uppercase tracking-wider text-[11px]">
          {label}
        </span>
        {icon && <span className="text-slate-400">{icon}</span>}
      </div>
      <div className={`text-2xl font-bold font-mono tracking-tight ${statusDecorators[status]}`}>
        {value}
      </div>
      {subValue && (
        <div className="text-[11px] text-slate-500 mt-1 font-mono truncate">
          {subValue}
        </div>
      )}
    </div>
  );
};
