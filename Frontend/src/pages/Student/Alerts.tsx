import React, { useEffect, useState } from "react";
import { Bell, AlertTriangle, CheckCircle, Info } from "lucide-react";

interface Alert {
  id: number;
  type: "attendance" | "event" | "faculty" | "achievement";
  message: string;
  date: string;
  sticky?: boolean; // pinned alerts
  level?: "safe" | "warning" | "danger"; // for attendance
}

export const Alerts: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);

  // Example: student attendance % (you can fetch from analytics later)
  const [attendance, setAttendance] = useState(72);

  useEffect(() => {
    const savedAlerts = localStorage.getItem("studentAlerts");
    if (savedAlerts) {
      setAlerts(JSON.parse(savedAlerts));
    } else {
      // Add a welcome alert for first-time users
      const initialAlert: Alert = {
        id: Date.now(),
        type: "faculty",
        message: "Welcome to the Smart Attendance Portal 🎓",
        date: new Date().toLocaleString(),
        sticky: true,
      };
      setAlerts([initialAlert]);
      localStorage.setItem("studentAlerts", JSON.stringify([initialAlert]));
    }
  }, []);

  // Auto-generate attendance alert
  useEffect(() => {
    let level: "safe" | "warning" | "danger" | undefined;
    if (attendance < 75) level = "danger";
    else if (attendance < 85) level = "warning";
    else level = "safe";

    const newAlert: Alert = {
      id: Date.now(),
      type: "attendance",
      message:
        level === "danger"
          ? `⚠️ Attendance dropped below 75% (Current: ${attendance}%)`
          : level === "warning"
          ? `⚠️ Attendance is in warning zone (Current: ${attendance}%)`
          : `✅ Great! Attendance is healthy (Current: ${attendance}%)`,
      date: new Date().toLocaleString(),
      level,
    };

    // prevent duplicates
    if (!alerts.find((a) => a.message === newAlert.message)) {
      const updatedAlerts = [...alerts, newAlert];
      setAlerts(updatedAlerts);
      localStorage.setItem("studentAlerts", JSON.stringify(updatedAlerts));
    }
  }, [attendance]);

  // Helper for styling
  const getAlertStyle = (alert: Alert) => {
    switch (alert.type) {
      case "attendance":
        if (alert.level === "danger")
          return "border-red-500/20 bg-red-500/5 text-red-600";
        if (alert.level === "warning")
          return "border-yellow-500/20 bg-yellow-500/5 text-yellow-600";
        return "border-green-500/20 bg-green-500/5 text-green-600";
      case "event":
        return "border-blue-500/20 bg-blue-500/5 text-blue-600";
      case "faculty":
        return "border-purple-500/20 bg-purple-500/5 text-purple-600";
      case "achievement":
        return "border-emerald-500/20 bg-emerald-500/5 text-emerald-600";
      default:
        return "border-border bg-muted text-muted-foreground";
    }
  };

  const getAlertIcon = (alert: Alert) => {
    switch (alert.type) {
      case "attendance":
        if (alert.level === "danger" || alert.level === "warning")
          return <AlertTriangle className="h-5 w-5" />;
        return <CheckCircle className="h-5 w-5" />;
      case "event":
      case "faculty":
      case "achievement":
        return <Info className="h-5 w-5" />;
      default:
        return <Bell className="h-5 w-5" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-foreground">📢 Alerts & Notifications</h2>
        <div className="text-sm text-muted-foreground">
          Stay updated with important notifications
        </div>
      </div>

      {alerts.length === 0 ? (
        <div className="glass p-8 rounded-xl text-center hover-glow transition-all duration-300">
          <Bell className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-muted-foreground">No alerts yet ✅</p>
        </div>
      ) : (
        <div className="space-y-4">
          {alerts
            .sort((a, b) => (a.sticky === b.sticky ? 0 : a.sticky ? -1 : 1)) // sticky always first
            .map((alert) => (
              <div
                key={alert.id}
                className={`glass border p-4 rounded-xl shadow-lg hover-glow transition-all duration-300 transform hover:scale-105 ${getAlertStyle(
                  alert
                )}`}
              >
                <div className="flex items-start space-x-3">
                  <div className="flex-shrink-0 mt-0.5">
                    {getAlertIcon(alert)}
                  </div>
                  <div className="flex-1">
                    <div className="flex justify-between items-start">
                      <p className="font-medium text-foreground">{alert.message}</p>
                      {alert.sticky && (
                        <span className="text-xs font-semibold text-purple-600 bg-purple-500/10 px-2 py-1 rounded-full border border-purple-500/20">
                          📌 Pinned
                        </span>
                      )}
                    </div>
                    <span className="text-xs block mt-2 text-muted-foreground">
                      {alert.date}
                    </span>
                  </div>
                </div>
              </div>
            ))}
        </div>
      )}
    </div>
  );
};
