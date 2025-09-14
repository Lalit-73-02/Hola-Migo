import React from "react";
import { PanelShell } from "../../components/PanelShell";
import { QrCode, History, FileText, BarChart3, Bell } from "lucide-react";
import { Outlet } from "react-router-dom";

interface StudentDashboardProps {
  onLogout: () => void;
}

export const StudentDashboard: React.FC<StudentDashboardProps> = ({ onLogout }) => {
  const navItems = [
    { label: "Dashboard", href: "/panel/student", icon: BarChart3 },
    { label: "Scan QR", href: "/panel/student/scanner", icon: QrCode },
    { label: "History", href: "/panel/student/history", icon: History },
    { label: "Leave", href: "/panel/student/leave", icon: FileText },
    { label: "Alerts", href: "/panel/student/alerts", icon: Bell },
  ];

  return (
    <PanelShell title="Attendo Student" navItems={navItems} onLogout={onLogout}>
      <div className="rounded-2xl shadow glass p-4 sm:p-6">
        {/* Render the nested route here */}
        <Outlet />
      </div>
    </PanelShell>
  );
};
