import React, { useState } from 'react';
import { HelpCircle, ChevronDown, ChevronUp, Sparkles, CheckCircle2, ArrowRight } from 'lucide-react';

interface GuidancePanelProps {
  stepNumber?: number | string;
  title: string;
  summary: string;
  recommendedAction?: string;
  whatToObserve?: string;
  onActionClick?: () => void;
  actionButtonLabel?: string;
  defaultExpanded?: boolean;
}

export const GuidancePanel: React.FC<GuidancePanelProps> = ({
  stepNumber,
  title,
  summary,
  recommendedAction,
  whatToObserve,
  onActionClick,
  actionButtonLabel,
  defaultExpanded = true,
}) => {
  const [isExpanded, setIsExpanded] = useState<boolean>(defaultExpanded);

  return (
    <div className="rounded-xl border border-indigo-100 bg-indigo-50/50 p-4 text-xs text-slate-700 shadow-2xs transition-all duration-200">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-indigo-600 text-[11px] font-mono font-bold text-white shadow-2xs">
            {stepNumber ? stepNumber : <Sparkles className="h-3 w-3" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono uppercase tracking-widest text-indigo-700 font-semibold">
                OPERATIONAL GUIDE
              </span>
              <span className="text-slate-300">&bull;</span>
              <h3 className="font-semibold text-slate-900 text-xs font-sans tracking-tight">
                {title}
              </h3>
            </div>
          </div>
        </div>

        <button
          onClick={() => setIsExpanded((prev) => !prev)}
          className="flex items-center gap-1 px-2 py-1 rounded text-[11px] font-mono text-slate-500 hover:text-slate-800 hover:bg-indigo-100/50 transition-colors cursor-pointer"
        >
          <span>{isExpanded ? 'Minimize' : 'Expand'}</span>
          {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>
      </div>

      {isExpanded && (
        <div className="mt-3 pt-3 border-t border-indigo-100 space-y-2.5 text-xs leading-relaxed">
          <p className="text-slate-600">{summary}</p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
            {recommendedAction && (
              <div className="bg-white p-3 rounded-lg border border-indigo-100/80 shadow-2xs">
                <span className="font-semibold text-indigo-900 text-[10px] uppercase font-mono tracking-wider block mb-1">
                  Target Objective
                </span>
                <span className="text-slate-700 text-xs leading-normal">{recommendedAction}</span>
              </div>
            )}
            {whatToObserve && (
              <div className="bg-white p-3 rounded-lg border border-indigo-100/80 shadow-2xs">
                <span className="font-semibold text-emerald-800 text-[10px] uppercase font-mono tracking-wider block mb-1">
                  Expected Telemetry
                </span>
                <span className="text-slate-700 text-xs leading-normal">{whatToObserve}</span>
              </div>
            )}
          </div>

          {onActionClick && actionButtonLabel && (
            <div className="pt-1">
              <button
                onClick={onActionClick}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-md text-xs font-medium shadow-2xs transition-colors cursor-pointer"
              >
                <span>{actionButtonLabel}</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
