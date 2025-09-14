import React from 'react';
import { PanelShell } from '../../components/PanelShell';
import { AnalyticsDashboard } from './AnalyticsDashboard';
import { AttendanceReports } from './AttendanceReports';
import { StudentManagement } from './StudentManagement';
import { QRCodeGenerator } from './QRCodeGenerator';
import { LeaveManagement } from './LeaveManagement';
import { QrCode, Users, FileText, BarChart3, Settings } from 'lucide-react';
import { useLocation } from 'react-router-dom';

interface AdminDashboardProps {
  onLogout: () => void;
}

export const AdminDashboard: React.FC<AdminDashboardProps> = ({ onLogout }) => {
  const location = useLocation();
  const navItems = [
    { label: 'Dashboard', href: '/panel/admin', icon: BarChart3 },
    { label: 'Attendance', href: '/panel/admin/attendance', icon: FileText },
    { label: 'Students', href: '/panel/admin/students', icon: Users },
    { label: 'Sessions', href: '/panel/admin/sessions', icon: QrCode },
    { label: 'Leave Management', href: '/panel/admin/settings', icon: Settings },
  ];

  return (
    <PanelShell title="Attendo Admin" navItems={navItems} onLogout={onLogout}>
      <div className="rounded-2xl shadow glass p-4 sm:p-6">
        {/\/panel\/admin\/?$/.test(location.pathname) && <AnalyticsDashboard />}
        {location.pathname.endsWith('/attendance') && <AttendanceReports />}
        {location.pathname.endsWith('/students') && <StudentManagement />}
        {location.pathname.endsWith('/sessions') && <QRCodeGenerator />}
        {location.pathname.endsWith('/settings') && <LeaveManagement />}
      </div>
    </PanelShell>
  );
};