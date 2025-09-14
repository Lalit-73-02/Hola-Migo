import React, { useMemo } from 'react';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
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
} from 'chart.js';
import { Users, TrendingUp, AlertTriangle, CheckCircle } from 'lucide-react';
import { storage } from '../../utils/storage';
import { format, subDays, eachDayOfInterval } from 'date-fns';

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

export const AnalyticsDashboard: React.FC = () => {
  const students = storage.getStudents();
  const attendanceRecords = storage.getAttendanceRecords();

  const analytics = useMemo(() => {
    const totalStudents = students.length;
    const totalDays = 20; // Mock semester days
    const present = attendanceRecords.filter(r => r.attendancePercentage >= 50).length;
    const absent = totalStudents * totalDays - present;
    const avgAttendance = students.reduce((sum, s) => sum + s.totalAttendance, 0) / totalStudents || 0;
    const lowAttendance = students.filter(s => s.totalAttendance < 75).length;

    // Generate last 7 days data
    const last7Days = eachDayOfInterval({
      start: subDays(new Date(), 6),
      end: new Date()
    }).map(date => {
      const dateStr = format(date, 'yyyy-MM-dd');
      const dayRecords = attendanceRecords.filter(r => r.date === dateStr);
      return {
        date: format(date, 'MMM dd'),
        attendance: dayRecords.length
      };
    });

    return {
      totalStudents,
      present,
      absent,
      avgAttendance: Math.round(avgAttendance),
      lowAttendance,
      last7Days
    };
  }, [students, attendanceRecords]);

  const lineChartData = {
    labels: analytics.last7Days.map(d => d.date),
    datasets: [
      {
        label: 'Daily Attendance',
        data: analytics.last7Days.map(d => d.attendance),
        borderColor: '#2563eb',
        backgroundColor: 'rgba(37, 99, 235, 0.1)',
        tension: 0.4,
        borderWidth: 3,
        pointBackgroundColor: '#2563eb',
        pointBorderColor: '#ffffff',
        pointBorderWidth: 2,
        pointRadius: 6,
        pointHoverRadius: 8,
      },
    ],
  };

  const barChartData = {
    labels: students.map(s => s.name.split(' ')[0]),
    datasets: [
      {
        label: 'Attendance %',
        data: students.map(s => s.totalAttendance),
        backgroundColor: students.map(s => s.totalAttendance >= 75 ? '#16a34a' : '#dc2626'),
        borderRadius: 8,
        borderSkipped: false,
        hoverBackgroundColor: students.map(s => s.totalAttendance >= 75 ? '#22c55e' : '#ef4444'),
      },
    ],
  };

  const doughnutData = {
    labels: ['Present', 'Absent'],
    datasets: [
      {
        data: [analytics.present, analytics.absent],
        backgroundColor: ['#16a34a', '#dc2626'],
        hoverBackgroundColor: ['#22c55e', '#ef4444'],
        hoverOffset: 4,
        borderWidth: 3,
        borderColor: '#ffffff',
      },
    ],
  };

  const statsCards = [
    {
      title: 'Total Students',
      value: analytics.totalStudents,
      icon: Users,
      color: 'blue',
    },
    {
      title: 'Average Attendance',
      value: `${analytics.avgAttendance}%`,
      icon: TrendingUp,
      color: 'green',
    },
    {
      title: 'Low Attendance',
      value: analytics.lowAttendance,
      icon: AlertTriangle,
      color: 'red',
    },
    {
      title: 'Present Today',
      value: analytics.last7Days[analytics.last7Days.length - 1]?.attendance || 0,
      icon: CheckCircle,
      color: 'green',
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-foreground">Analytics Dashboard</h2>
        <div className="text-sm text-muted-foreground">
          Overview of attendance trends and statistics
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statsCards.map((stat, index) => {
          const Icon = stat.icon;
          const colorClasses = {
            blue: 'bg-blue-500 text-blue-50',
            green: 'bg-green-500 text-green-50',
            red: 'bg-red-500 text-red-50',
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
            Attendance Trend (Last 7 Days)
          </h3>
          <div className="hover:shadow-[0_0_30px_rgba(37,99,235,0.3)] transition-shadow duration-300 rounded-lg p-2">
            <Line data={lineChartData} options={{ responsive: true }} />
          </div>
        </div>

        {/* Doughnut Chart */}
        <div className="glass p-6 rounded-xl shadow-lg hover-glow transition-all duration-300 transform hover:scale-105">
          <h3 className="text-lg font-semibold text-foreground mb-4">
            Overall Attendance Distribution
          </h3>
          <div className="w-64 mx-auto hover:shadow-[0_0_30px_rgba(22,163,74,0.3)] transition-shadow duration-300 rounded-lg p-2">
            <Doughnut data={doughnutData} options={{ responsive: true }} />
          </div>
        </div>
      </div>

      {/* Bar Chart */}
      <div className="glass p-6 rounded-xl shadow-lg hover-glow transition-all duration-300 transform hover:scale-105">
        <h3 className="text-lg font-semibold text-foreground mb-4">
          Individual Student Attendance
        </h3>
        <div className="hover:shadow-[0_0_30px_rgba(220,38,38,0.3)] transition-shadow duration-300 rounded-lg p-2">
          <Bar 
            data={barChartData} 
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
    </div>
  );
};