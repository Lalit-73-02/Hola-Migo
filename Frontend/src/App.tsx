import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { ThemeProvider } from "@/hooks/useTheme";
import { AuthProvider, useAuth } from "@/hooks/useAuth";

import { AdminDashboard } from "./pages/Admin/AdminDashboard";
import { StudentDashboard } from "./pages/Student/StudentDashboard";
import { QRScanner } from "./pages/Student/QRScanner";
import { AttendanceHistory } from "./pages/Student/AttendanceHistory";
import { LeaveApplication } from "./pages/Student/LeaveApplication";
import { StudentAnalytics } from "./pages/Student/StudentAnalytics";
import { Alerts } from "./pages/Student/Alerts";

import NotFound from "./pages/NotFound";
import ProtectedRoute from "@/components/ProtectedRoute";
import Home from "./pages/Home";

const queryClient = new QueryClient();

const AdminRoute = () => {
  const { logout } = useAuth();
  return <AdminDashboard onLogout={logout} />;
};

const StudentRoute = () => {
  const { logout } = useAuth();
  return <StudentDashboard onLogout={logout} />;
};

const App = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ThemeProvider defaultTheme="light" storageKey="attendo-ui-theme">
          <TooltipProvider>
            <Toaster />
            <Sonner />
            <BrowserRouter>
              <Routes>
                <Route path="/" element={<Home />} />

                {/* Redirects */}
                <Route path="/admin" element={<Navigate to="/panel/admin" replace />} />
                <Route path="/student" element={<Navigate to="/panel/student" replace />} />
                <Route path="/AdminDashboard" element={<Navigate to="/panel/admin" replace />} />
                <Route path="/StudentDashboard" element={<Navigate to="/panel/student" replace />} />

                {/* Admin Panel */}
                <Route
                  path="/panel/admin/*"
                  element={
                    <ProtectedRoute requiredRole="admin">
                      <AdminRoute />
                    </ProtectedRoute>
                  }
                />

                {/* Student Panel (Nested Routes) */}
                <Route
                  path="/panel/student/*"
                  element={
                    <ProtectedRoute requiredRole="student">
                      <StudentRoute />
                    </ProtectedRoute>
                  }
                >
                  <Route index element={<StudentAnalytics />} />
                  <Route path="scanner" element={<QRScanner />} />
                  <Route path="history" element={<AttendanceHistory />} />
                  <Route path="leave" element={<LeaveApplication />} />
                  <Route path="alerts" element={<Alerts />} />
                </Route>

                {/* Fallback */}
                <Route path="*" element={<NotFound />} />
              </Routes>
            </BrowserRouter>
          </TooltipProvider>
        </ThemeProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
};

export default App;
