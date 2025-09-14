import { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';

interface ProtectedRouteProps {
  children: ReactNode;
  requiredRole?: 'admin' | 'student';
}

export default function ProtectedRoute({ children, requiredRole }: ProtectedRouteProps) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/" replace />;
  }

  if (requiredRole && user.role !== requiredRole) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="max-w-md w-full glass rounded-2xl p-6 text-center">
          <h2 className="text-2xl font-semibold mb-2">Access denied</h2>
          <p className="text-muted-foreground mb-4">You don't have permission to view this page.</p>
          <div className="space-x-2">
            <a href="/" className="inline-flex items-center px-4 py-2 rounded-xl bg-primary text-primary-foreground hover-glow">Go Home</a>
          </div>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}