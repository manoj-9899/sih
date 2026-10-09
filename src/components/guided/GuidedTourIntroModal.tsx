import React from 'react';
import { ShieldCheck, Compass, Sparkles, X, ArrowRight } from 'lucide-react';

interface GuidedTourIntroModalProps {
  isOpen: boolean;
  onStartTour: () => void;
  onDismiss: () => void;
}

export const GuidedTourIntroModal: React.FC<GuidedTourIntroModalProps> = ({
  isOpen,
  onStartTour,
  onDismiss,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs animate-in fade-in duration-200">
      <div className="max-w-xl w-full bg-white rounded-2xl shadow-2xl border border-slate-200 overflow-hidden font-sans text-slate-800">
        {/* Header Banner */}
        <div className="bg-gradient-to-br from-indigo-900 via-indigo-800 to-slate-900 p-6 sm:p-8 text-white relative">
          <button
            onClick={onDismiss}
            className="absolute top-4 right-4 p-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-white/80 hover:text-white transition-colors cursor-pointer"
            title="Close"
          >
            <X className="w-4 h-4" />
          </button>

          <div className="flex items-center gap-2 mb-3">
            <span className="px-2.5 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-400/30 text-[11px] font-mono uppercase tracking-wider font-semibold">
              Quick 3-Minute Interactive Tour
            </span>
          </div>

          <h2 className="text-xl sm:text-2xl font-bold tracking-tight mb-2">
            How to Catch a Secret Document Leaker
          </h2>
          <p className="text-indigo-200 text-xs sm:text-sm leading-relaxed">
            When confidential files are sent to multiple people and someone leaks them online, all copies normally look identical—making it impossible to know who did it.
            <br className="hidden sm:inline" /> In this quick tour, you will see how we use invisible digital watermarks to catch the leaker red-handed.
          </p>
        </div>

        {/* 4 Simple Steps Preview */}
        <div className="p-6 space-y-4 text-xs sm:text-sm text-slate-600">
          <div className="space-y-2">
            <h4 className="font-bold text-slate-900 text-xs uppercase tracking-wider font-mono">
              The 5-Step Detective Mission:
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200/80 space-y-1">
                <div className="font-semibold text-slate-900 text-xs flex items-center gap-1.5">
                  <span className="w-5 h-5 rounded-full bg-indigo-100 text-indigo-700 flex items-center justify-center text-[11px] font-mono font-bold">1</span>
                  Lock the Document
                </div>
                <p className="text-[11px] text-slate-500 leading-normal">
                  Put a secret file inside a digital safe. We give personal keys only to Alice and Bob.
                </p>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200/80 space-y-1">
                <div className="font-semibold text-slate-900 text-xs flex items-center gap-1.5">
                  <span className="w-5 h-5 rounded-full bg-indigo-100 text-indigo-700 flex items-center justify-center text-[11px] font-mono font-bold">2</span>
                  Stamp Invisible Watermark
                </div>
                <p className="text-[11px] text-slate-500 leading-normal">
                  When they open the file, an invisible code is stamped between the words on screen.
                </p>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200/80 space-y-1">
                <div className="font-semibold text-slate-900 text-xs flex items-center gap-1.5">
                  <span className="w-5 h-5 rounded-full bg-indigo-100 text-indigo-700 flex items-center justify-center text-[11px] font-mono font-bold">3</span>
                  Bob Leaks His Copy
                </div>
                <p className="text-[11px] text-slate-500 leading-normal">
                  Bob shares his copy on a public website, thinking nobody can tell it came from him.
                </p>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200/80 space-y-1">
                <div className="font-semibold text-slate-900 text-xs flex items-center gap-1.5">
                  <span className="w-5 h-5 rounded-full bg-indigo-100 text-indigo-700 flex items-center justify-center text-[11px] font-mono font-bold">4</span>
                  Catch the Leaker
                </div>
                <p className="text-[11px] text-slate-500 leading-normal">
                  Scan the leaked text to reveal Bob&apos;s hidden watermark and prove his guilt.
                </p>
              </div>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-amber-50 border border-amber-200/80 text-amber-900 text-xs flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-amber-600 shrink-0" />
            <span>
              <strong>No technical skills needed!</strong> Follow the simple steps, or click <strong>&quot;Auto-do this step&quot;</strong> at any time to let the app do the work.
            </span>
          </div>
        </div>

        {/* Modal Actions */}
        <div className="p-4 sm:p-6 bg-slate-50 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between gap-3">
          <button
            onClick={onDismiss}
            className="text-xs text-slate-500 hover:text-slate-800 transition-colors cursor-pointer order-2 sm:order-1"
          >
            Skip tour and explore on my own
          </button>

          <button
            onClick={onStartTour}
            className="w-full sm:w-auto flex items-center justify-center gap-2 px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-semibold shadow-md hover:shadow-lg transition-all cursor-pointer order-1 sm:order-2"
          >
            <Compass className="w-4 h-4" />
            <span>Start the Tour</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
