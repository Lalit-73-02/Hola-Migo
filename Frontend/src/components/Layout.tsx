import React from 'react';
import { LogOut, User, UserCheck } from 'lucide-react';
import { storage } from '../utils/storage';
import { ThemeToggle } from '@/components/ui/theme-toggle';

interface LayoutProps {
  children: React.ReactNode;
  title: string;
  onLogout: () => void;
}

export const Layout: React.FC<LayoutProps> = ({ children, title, onLogout }) => {
  const currentUser = storage.getCurrentUser();

  return (
    <div className="min-h-screen bg-background">
      <nav className="glass border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <UserCheck className="h-8 w-8 text-primary mr-3" />
              <h1 className="text-xl font-semibold gradient-text">{title}</h1>
            </div>
            <div className="flex items-center space-x-4">
              <ThemeToggle />
              <div className="hidden sm:flex items-center space-x-2">
                <User className="h-5 w-5 text-muted-foreground" />
                <span className="text-sm text-foreground">{currentUser?.name}</span>
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-primary/10 text-primary">
                  {currentUser?.role}
                </span>
              </div>
              <button
                onClick={onLogout}
                className="flex items-center space-x-1 px-3 py-2 rounded-md text-sm font-medium text-foreground hover:text-primary hover:bg-primary/10 transition-colors"
              >
                <LogOut className="h-4 w-4" />
                <span>Logout</span>
              </button>
            </div>
          </div>
        </div>
      </nav>
      <main className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        {children}
      </main>
    </div>
  );
};