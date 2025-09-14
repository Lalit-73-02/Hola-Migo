import React, { useState } from 'react';
import { Link, NavLink } from 'react-router-dom';
import { Menu, X, Search, User, LogOut, UserCheck } from 'lucide-react';
import { ThemeToggle } from '@/components/ui/theme-toggle';
import { Input } from '@/components/ui/input';

interface NavItem {
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>; 
}

interface PanelShellProps {
  title: string;
  navItems: NavItem[];
  children: React.ReactNode;
  onLogout: () => void;
}

export function PanelShell({ title, navItems, children, onLogout }: PanelShellProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen bg-background">
      {/* Topbar */}
      <header className="fixed top-0 left-0 right-0 z-40 glass">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <button className="md:hidden" onClick={() => setSidebarOpen(!sidebarOpen)} aria-label="Toggle sidebar">
              {sidebarOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>
            <Link to="/" className="flex items-center space-x-2">
              <UserCheck className="h-6 w-6 text-primary" />
              <span className="font-semibold gradient-text">{title}</span>
            </Link>
          </div>
          <div className="hidden md:flex items-center space-x-3 w-full max-w-lg mx-6">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Search..." className="pl-9 rounded-xl text-foreground placeholder:text-muted-foreground" />
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <ThemeToggle />
            <button onClick={onLogout} className="hidden sm:inline-flex items-center space-x-1 px-3 py-2 rounded-xl text-sm hover-glow">
              <LogOut className="h-4 w-4" />
              <span>Sign out</span>
            </button>
            <div className="inline-flex sm:hidden p-2 rounded-xl hover-glow">
              <User className="h-5 w-5" />
            </div>
          </div>
        </div>
      </header>

      {/* Sidebar */}
      <aside className={`fixed top-16 left-0 bottom-0 z-30 w-64 glass transform transition-transform ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'} md:translate-x-0`}>
        <nav className="h-full overflow-y-auto px-3 py-4 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.href}
                to={item.href}
                className={({ isActive }) =>
                  `flex items-center space-x-3 px-3 py-2 rounded-xl text-sm transition-all duration-200 hover-glow ${
                    isActive ? 'bg-primary/10 text-primary scale-[1.02]' : 'text-muted-foreground hover:text-foreground'
                  }`
                }
                onClick={() => setSidebarOpen(false)}
              >
                <Icon className="h-4 w-4" />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </nav>
      </aside>

      {/* Content */}
      <main className="pt-16 md:pl-64">
        <div className="max-w-7xl mx-auto px-4 md:px-6 py-6">
          {children}
        </div>
      </main>
    </div>
  );
}


