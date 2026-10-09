import React, { useState } from 'react';
import {
  Compass,
  ArrowRight,
  ArrowLeft,
  Sparkles,
  ChevronDown,
  ChevronUp,
  X,
  Play,
} from 'lucide-react';
import { TOUR_STEPS, TourStep } from '../../types/tour';
import { ActiveTab } from '../../types/navigation';

interface FloatingMissionGuideProps {
  currentStepId: number;
  onSelectStep: (stepId: number) => void;
  onNavigateTab: (tab: ActiveTab) => void;
  onCloseTour: () => void;
  onAutoExecuteCurrentStep: () => void;
  activePackageAvailable: boolean;
  leakedTextAvailable: boolean;
}

export const FloatingMissionGuide: React.FC<FloatingMissionGuideProps> = ({
  currentStepId,
  onSelectStep,
  onNavigateTab,
  onCloseTour,
  onAutoExecuteCurrentStep,
  activePackageAvailable,
  leakedTextAvailable,
}) => {
  const [isMinimized, setIsMinimized] = useState<boolean>(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState<boolean>(false);

  const stepIndex = Math.max(0, Math.min(TOUR_STEPS.length - 1, currentStepId - 1));
  const step = TOUR_STEPS[stepIndex];

  const handleNext = () => {
    if (stepIndex < TOUR_STEPS.length - 1) {
      const nextStep = TOUR_STEPS[stepIndex + 1];
      onSelectStep(nextStep.id);
      onNavigateTab(nextStep.tabKey);
    } else {
      onCloseTour();
    }
  };

  const handlePrev = () => {
    if (stepIndex > 0) {
      const prevStep = TOUR_STEPS[stepIndex - 1];
      onSelectStep(prevStep.id);
      onNavigateTab(prevStep.tabKey);
    }
  };

  const handleGoToTab = () => {
    onNavigateTab(step.tabKey);
  };

  if (isMinimized) {
    return (
      <div className="fixed bottom-6 right-6 z-50">
        <button
          onClick={() => setIsMinimized(false)}
          className="flex items-center gap-2 px-4 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-full shadow-lg text-xs font-semibold tracking-wide transition-all cursor-pointer ring-4 ring-indigo-100 hover:scale-105"
        >
          <Compass className="w-4 h-4 animate-spin-slow" />
          <span>Resume Guided Tour ({step.id}/{TOUR_STEPS.length})</span>
        </button>
      </div>
    );
  }

  return (
    <div className="fixed bottom-6 right-6 z-50 max-w-md w-[calc(100vw-3rem)] sm:w-[440px] bg-white/95 backdrop-blur-md rounded-2xl border border-indigo-200/90 shadow-2xl overflow-hidden font-sans transition-all text-slate-800 ring-1 ring-slate-900/5">
      {/* Top Banner with Progress & Controls */}
      <div className="bg-gradient-to-r from-indigo-700 via-indigo-600 to-indigo-800 px-4 py-3 text-white flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="w-6 h-6 rounded-full bg-white/20 flex items-center justify-center text-xs font-bold font-mono">
            {step.id}
          </div>
          <div>
            <div className="text-[10px] font-mono tracking-wider uppercase text-indigo-200">
              STEP {step.id} OF {TOUR_STEPS.length} &bull; DETECTIVE STORY
            </div>
            <div className="text-xs font-bold leading-tight truncate max-w-[240px]">
              {step.title}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1">
          <button
            onClick={() => setIsMinimized(true)}
            title="Minimize Guide"
            className="p-1 rounded-md hover:bg-white/15 text-indigo-100 hover:text-white transition-colors cursor-pointer"
          >
            <ChevronDown className="w-4 h-4" />
          </button>
          <button
            onClick={onCloseTour}
            title="Exit Tour"
            className="p-1 rounded-md hover:bg-white/15 text-indigo-100 hover:text-white transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Progress Dots Bar */}
      <div className="flex bg-indigo-50 border-b border-indigo-100 px-4 py-1.5 gap-1.5 justify-between">
        {TOUR_STEPS.map((s, idx) => {
          const isActive = idx === stepIndex;
          const isDone = idx < stepIndex;
          return (
            <button
              key={s.id}
              onClick={() => {
                onSelectStep(s.id);
                onNavigateTab(s.tabKey);
              }}
              className={`flex-1 h-1.5 rounded-full transition-all cursor-pointer ${
                isActive
                  ? 'bg-indigo-600 ring-2 ring-indigo-300'
                  : isDone
                  ? 'bg-emerald-500'
                  : 'bg-slate-200 hover:bg-slate-300'
              }`}
              title={`Step ${s.id}: ${s.title}`}
            />
          );
        })}
      </div>

      {/* Main Narrative Card Content */}
      <div className="p-4 space-y-3.5 max-h-[60vh] overflow-y-auto text-xs">
        {/* Story Scenario Box */}
        <div className="bg-indigo-50/70 border border-indigo-100 p-3 rounded-xl flex items-start gap-2.5">
          <Sparkles className="w-4 h-4 text-indigo-600 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-semibold text-indigo-950 text-[11px] block">
              What&apos;s happening:
            </span>
            <p className="text-slate-600 leading-relaxed text-[11px]">
              {step.storyAnalogy}
            </p>
          </div>
        </div>

        {/* Current Objective / Call to Action */}
        <div className="bg-amber-50/80 border border-amber-200/80 p-3 rounded-xl space-y-1.5">
          <div className="flex items-center gap-1.5 text-amber-900 font-bold text-[11px] font-mono uppercase tracking-wider">
            <span className="w-2 h-2 rounded-full bg-amber-500 animate-ping" />
            What you should do:
          </div>
          <div className="text-slate-800 font-medium leading-relaxed whitespace-pre-line">
            {step.targetObjective}
          </div>
        </div>

        {/* What happens next preview */}
        {step.whatHappensNext && (
          <div className="bg-emerald-50/80 border border-emerald-200/80 p-2.5 rounded-xl space-y-0.5">
            <span className="text-[10px] font-mono uppercase text-emerald-800 tracking-wider font-semibold block">
              What happens next:
            </span>
            <p className="text-slate-700 leading-relaxed text-[11px]">
              {step.whatHappensNext}
            </p>
          </div>
        )}

        {/* Why this matters */}
        <div className="space-y-1">
          <span className="text-[10px] font-mono uppercase text-slate-500 tracking-wider font-semibold">
            Why this matters:
          </span>
          <p className="text-slate-600 leading-relaxed text-[11px]">
            {step.whyThisMatters}
          </p>
        </div>

        {/* Expandable Technical Deep-Dive for curious users */}
        <div className="border-t border-slate-100 pt-2">
          <button
            onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
            className="flex items-center justify-between w-full text-[10px] font-mono text-slate-500 hover:text-slate-900 cursor-pointer"
          >
            <span>For curious learners: What the math did</span>
            {showTechnicalDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
          {showTechnicalDetails && (
            <p className="mt-1.5 p-2 bg-slate-50 rounded-lg border border-slate-200 text-slate-700 text-[10px] font-mono leading-relaxed">
              {step.behindTheScenesExplanation}
            </p>
          )}
        </div>
      </div>

      {/* Action Footer Bar */}
      <div className="bg-slate-50 border-t border-slate-200/80 px-4 py-3 flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5">
          <button
            onClick={handlePrev}
            disabled={stepIndex === 0}
            className="p-1.5 rounded-lg border border-slate-200 bg-white text-slate-600 hover:text-slate-900 hover:bg-slate-100 disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer transition-colors"
            title="Previous Step"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
          </button>

          {/* Quick Auto-Do Failsafe Button */}
          <button
            onClick={onAutoExecuteCurrentStep}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-indigo-200 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 font-medium text-[11px] cursor-pointer transition-colors"
            title="Let the app complete this step automatically"
          >
            <Play className="w-3 h-3 text-indigo-600" />
            <span>⚡ Auto-do this step</span>
          </button>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleGoToTab}
            className="text-[11px] font-medium text-slate-500 hover:text-indigo-600 underline cursor-pointer"
          >
            Switch to tab
          </button>

          <button
            onClick={handleNext}
            className="flex items-center gap-1 px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold shadow-sm transition-all cursor-pointer hover:shadow"
          >
            <span>{stepIndex === TOUR_STEPS.length - 1 ? 'Finish Tour' : 'Next Step'}</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
