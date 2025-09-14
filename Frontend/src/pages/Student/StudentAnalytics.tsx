import React, { useMemo } from "react";
import {
  Line,
  Doughnut,
  Bar
} from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from "chart.js";
import {
  Calendar,
  CheckCircle,
  XCircle,
  AlertTriangle,
  TrendingUp,
} from "lucide-react";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

export const StudentAnalytics: React.FC = () => {
  // ✅ Example mock data
  const overallAttendance = 72;
  const daysPresent = 123;
  const daysAbsent = 47;
  const lowAttendance = overallAttendance < 75;

  const trendData = useMemo(() => ({
    labels: ["Mon", "Tue", "Wed", "Thu", "Fri"],
    datasets: [
      {
        label: "Attendance %",
        data: [80, 70, 75, 68, 72],
        borderColor: "rgb(59, 130, 246)",
        backgroundColor: "rgba(59, 130, 246, 0.5)",
        tension: 0.4,
        borderWidth: 3,
        pointBackgroundColor: '#3b82f6',
        pointBorderColor: '#ffffff',
        pointBorderWidth: 2,
        pointRadius: 6,
        pointHoverRadius: 8,
      },
    ],
  }), []);

  const distributionData = useMemo(() => ({
    labels: ["Present", "Absent"],
    datasets: [
      {
        label: "Days",
        data: [daysPresent, daysAbsent],
        backgroundColor: ["#22c55e", "#ef4444"],
        hoverBackgroundColor: ["#16a34a", "#dc2626"],
        hoverOffset: 4,
        borderWidth: 3,
        borderColor: '#ffffff',
      },
    ],
  }), [daysPresent, daysAbsent]);

  const weeklyData = useMemo(() => ({
    labels: ["Week 1", "Week 2", "Week 3", "Week 4"],
    datasets: [
      {
        label: "Attendance %",
        data: [85, 75, 70, 72],
        backgroundColor: "rgba(59, 130, 246, 0.8)",
        borderRadius: 8,
        borderSkipped: false,
        hoverBackgroundColor: "rgba(59, 130, 246, 1)",
      },
    ],
  }), []);

  const statsCards = [
    {
      title: 'Overall Attendance',
      value: `${overallAttendance}%`,
      icon: TrendingUp,
      color: 'blue',
    },
    {
      title: 'Days Present',
      value: daysPresent,
      icon: CheckCircle,
      color: 'green',
    },
    {
      title: 'Days Absent',
      value: daysAbsent,
      icon: XCircle,
      color: 'red',
    },
    {
      title: 'Target',
      value: '75%',
      icon: Calendar,
      color: 'yellow',
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-foreground">Student Analytics</h2>
        <div className="text-sm text-muted-foreground">
          Your attendance performance overview
        </div>
      </div>


           {/* Alerts Section */}
           {lowAttendance && (
        <div className="glass p-6 rounded-xl shadow-lg border border-red-500 hover-glow transition-all duration-300">
          <div className="flex items-center space-x-3">
            <AlertTriangle className="h-6 w-6 text-red-500" />
            <h3 className="text-lg font-semibold text-red-500">Low Attendance Alert</h3>
          </div>
          <p className="mt-2 text-muted-foreground">
            Your attendance is below the required 75%. Please attend more classes to avoid
            being debarred from exams.
          </p>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statsCards.map((stat, index) => {
          const Icon = stat.icon;
          const colorClasses = {
            blue: 'bg-blue-500 text-blue-50',
            green: 'bg-green-500 text-green-50',
            red: 'bg-red-500 text-red-50',
            yellow: 'bg-yellow-500 text-yellow-50',
          };

          return (
            <div key={index} className="glass p-6 rounded-xl shadow-lg hover-glow transition-all duration-300 transform hover:scale-105">
              <div className="flex items-center">
                <div className={`p-3 rounded-lg ${colorClasses[stat.color as keyof typeof colorClasses]} shadow-lg`}>
                  <Icon className="h-6 w-6" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-muted-foreground">{stat.title}</p>
                  <p className="text-2xl font-bold text-foreground">{stat.value}</p>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Line Chart */}
        <div className="glass p-6 rounded-xl shadow-lg hover-glow transition-all duration-300 transform hover:scale-105">
          <h3 className="text-lg font-semibold text-foreground mb-4">
            Attendance Trend
          </h3>
          <div className="hover:shadow-[0_0_30px_rgba(59,130,246,0.3)] transition-shadow duration-300 rounded-lg p-2">
            <Line data={trendData} options={{ responsive: true }} />
          </div>
        </div>

        {/* Doughnut Chart */}
        <div className="glass p-6 rounded-xl shadow-lg hover-glow transition-all duration-300 transform hover:scale-105">
          <h3 className="text-lg font-semibold text-foreground mb-4">
            Attendance Distribution
          </h3>
          <div className="w-64 mx-auto hover:shadow-[0_0_30px_rgba(34,197,94,0.3)] transition-shadow duration-300 rounded-lg p-2">
            <Doughnut data={distributionData} options={{ responsive: true }} />
          </div>
        </div>
      </div>

      {/* Bar Chart */}
      <div className="glass p-6 rounded-xl shadow-lg hover-glow transition-all duration-300 transform hover:scale-105">
        <h3 className="text-lg font-semibold text-foreground mb-4">
          Weekly Performance
        </h3>
        <div className="hover:shadow-[0_0_30px_rgba(59,130,246,0.3)] transition-shadow duration-300 rounded-lg p-2">
          <Bar 
            data={weeklyData} 
            options={{ 
              responsive: true,
              plugins: {
                legend: {
                  display: false
                }
              },
              scales: {
                y: {
                  beginAtZero: true,
                  max: 100
                }
              }
            }} 
          />
        </div>
      </div>

 

      {/* Student Info */}
      <div className="glass p-6 rounded-xl shadow-lg hover-glow transition-all duration-300 transform hover:scale-105">
        <h3 className="text-lg font-semibold text-foreground mb-4">Student Information</h3>
        <ul className="space-y-2 text-muted-foreground">
          <li><strong className="text-foreground">ID:</strong> STU123</li>
          <li><strong className="text-foreground">Department:</strong> Computer Science</li>
          <li><strong className="text-foreground">Year:</strong> 3rd</li>
          <li><strong className="text-foreground">Email:</strong> student@example.com</li>
          <li><strong className="text-foreground">Goal:</strong> Maintain 75% attendance</li>
        </ul>
      </div>
    </div>
  );
};
