import React from 'react';
import {
  Compass,
  FileText,
  Users,
  Unlock,
  Search,
  Database,
  KeyRound,
  ShieldCheck,
  Activity,
  Settings,
  Shield,
  ChevronLeft,
  ChevronRight,
  Menu,
  X,
} from 'lucide-react';
import { ActiveTab } from '../types/navigation';

interface SidebarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  blocksCount: number;
  collapsed: boolean;
  onToggleCollapse: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

interface NavItemDef {
  id: ActiveTab;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
}

interface NavSectionDef {
  title: string;
  items: NavItemDef[];
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  blocksCount,
  collapsed,
  onToggleCollapse,
  mobileOpen,
  onCloseMobile,
}) => {
  const navSections: NavSectionDef[] = [
    {
      title: 'WORKSPACE',
      items: [
        { id: 'overview', label: 'Overview', icon: Compass },
        { id: 'documents', label: 'Documents', icon: FileText },
        { id: 'recipients', label: 'Recipients', icon: Users },
        { id: 'decrypt', label: 'Decrypt', icon: Unlock },
      ],
    },
    {
      title: 'INVESTIGATION',
      items: [
        { id: 'forensics', label: 'Forensics', icon: Search },
        {
          id: 'ledger',
          label: 'Ledger',
          icon: Database,
          badge: `Block ${blocksCount}`,
        },
      ],
    },
    {
      title: 'SECURITY',
      items: [
        { id: 'identity', label: 'Identity', icon: KeyRound },
        { id: 'verification', label: 'Verification', icon: ShieldCheck },
        { id: 'audit', label: 'Audit Center', icon: Activity },
      ],
    },
    {
      title: 'SYSTEM',
      items: [{ id: 'settings', label: 'Settings', icon: Settings }],
    },
  ];

  const handleSelectTab = (tab: ActiveTab) => {
    setActiveTab(tab);
    onCloseMobile();
  };

  const navContent = (
    <div className="flex flex-col h-full bg-white select-none">
      {/* Brand Header */}
      <div className="h-14 border-b border-slate-200/90 flex items-center justify-between px-4 shrink-0">
        {!collapsed && (
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-7 h-7 rounded-lg bg-indigo-600 flex items-center justify-center text-white shrink-0 shadow-2xs">
              <Shield className="w-4 h-4" />
            </div>
            <div className="truncate">
              <div className="text-xs font-semibold text-slate-900 tracking-tight flex items-center gap-1.5">
                AEGIS-PQC
                <span className="text-[10px] font-mono text-indigo-700 bg-indigo-50 px-1 py-0.5 rounded border border-indigo-100 font-medium">
                  FIPS
                </span>
              </div>
              <div className="text-[10px] text-slate-500 truncate">
                Provenance &amp; Attribution
              </div>
            </div>
          </div>
        )}

        {collapsed && (
          <div className="mx-auto w-7 h-7 rounded-lg bg-indigo-600 flex items-center justify-center text-white shadow-2xs">
            <Shield className="w-4 h-4" />
          </div>
        )}

        {/* Desktop collapse toggle */}
        <button
          onClick={onToggleCollapse}
          className="hidden lg:flex p-1.5 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded-md transition-colors cursor-pointer"
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>

        {/* Mobile close toggle */}
        <button
          onClick={onCloseMobile}
          className="lg:hidden p-1.5 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded-md transition-colors cursor-pointer"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Nav Items List */}
      <nav className="flex-1 overflow-y-auto p-3 space-y-4">
        {navSections.map((sec, secIdx) => (
          <div key={secIdx} className="space-y-1">
            {!collapsed && (
              <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider px-2 py-1">
                {sec.title}
              </div>
            )}
            <div className="space-y-0.5">
              {sec.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;

                return (
                  <button
                    key={item.id}
                    onClick={() => handleSelectTab(item.id)}
                    title={collapsed ? item.label : undefined}
                    className={`w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all text-left cursor-pointer group ${
                      isActive
                        ? 'bg-slate-100 text-indigo-700 font-semibold'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                    }`}
                  >
                    <Icon
                      className={`w-4 h-4 shrink-0 transition-colors ${
                        isActive ? 'text-indigo-600' : 'text-slate-400 group-hover:text-slate-600'
                      }`}
                    />
                    {!collapsed && (
                      <span className="flex-1 truncate">{item.label}</span>
                    )}
                    {!collapsed && item.badge && (
                      <span className="text-[10px] font-mono text-slate-500 bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200/80">
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Static Footer Status */}
      <div className="p-3 border-t border-slate-200/90 bg-slate-50/60 shrink-0">
        {!collapsed ? (
          <div className="text-[11px] flex items-center justify-between text-slate-500 font-sans">
            <span className="flex items-center gap-1.5 font-medium">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              Air-Gapped Local
            </span>
            <span className="font-mono text-[10px] text-slate-400">4/4 Nodes</span>
          </div>
        ) : (
          <div className="flex justify-center" title="Air-Gapped: 4/4 Nodes Active">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
          </div>
        )}
      </div>
    </div>
  );

  return (
    <>
      {/* 1. Desktop Fixed Sidebar */}
      <aside
        className={`hidden lg:block fixed inset-y-0 left-0 z-30 border-r border-slate-200/90 bg-white transition-all duration-200 ${
          collapsed ? 'w-16' : 'w-64'
        }`}
      >
        {navContent}
      </aside>

      {/* 2. Mobile Backdrop & Slide Drawer */}
      {mobileOpen && (
        <div className="lg:hidden fixed inset-0 z-50 flex">
          <div
            className="fixed inset-0 bg-slate-900/40 backdrop-blur-xs transition-opacity"
            onClick={onCloseMobile}
          />
          <div className="relative w-64 max-w-[80vw] h-full shadow-2xl z-10">
            {navContent}
          </div>
        </div>
      )}
    </>
  );
};
