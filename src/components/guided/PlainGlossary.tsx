import React from 'react';
import { HelpCircle } from 'lucide-react';

interface PlainGlossaryProps {
  term: string;
  simpleDefinition: string;
  children: React.ReactNode;
}

export const PlainGlossary: React.FC<PlainGlossaryProps> = ({
  term,
  simpleDefinition,
  children,
}) => {
  return (
    <span className="relative group inline-flex items-center gap-0.5 cursor-help">
      <span className="border-b border-dotted border-slate-400 group-hover:border-indigo-600 transition-colors">
        {children}
      </span>
      <HelpCircle className="w-3 h-3 text-slate-400 group-hover:text-indigo-600 transition-colors inline shrink-0" />

      {/* Floating Plain-English Tooltip */}
      <span className="pointer-events-none absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-64 p-2.5 bg-slate-900 text-white rounded-lg shadow-xl text-[11px] font-sans leading-snug opacity-0 group-hover:opacity-100 transition-opacity duration-150 z-50">
        <span className="font-semibold text-indigo-300 block mb-0.5">{term}</span>
        <span className="text-slate-200">{simpleDefinition}</span>
        <span className="absolute top-full left-1/2 -translate-x-1/2 border-4 border-transparent border-t-slate-900"></span>
      </span>
    </span>
  );
};
