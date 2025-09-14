import React, { useState } from 'react';
import { Calendar, Filter, CheckCircle, XCircle, Clock } from 'lucide-react';
import { storage } from '../../utils/storage';
import { format } from 'date-fns';
import { useAuth } from '@/hooks/useAuth';

export const AttendanceHistory: React.FC = () => {
  const { user: authUser } = useAuth();
  const students = storage.getStudents();
  const attendanceRecords = storage.getAttendanceRecords();
  
  const currentStudent = React.useMemo(() => {
    const byId = students.find(s => s.id === authUser?.id);
    if (byId) return byId;
    const byEmail = students.find(s => s.email === authUser?.email);
    if (byEmail) return byEmail;
    if (authUser && authUser.role === 'student') {
      return {
        id: authUser.id,
        name: authUser.name,
        email: authUser.email,
        role: 'student',
        studentId: (authUser as any).studentId || `TEMP-${authUser.id.slice(0, 6)}`,
        department: 'Unknown',
        year: 1,
        phoneNumber: '',
        totalAttendance: 0,
        presentDays: 0,
        totalDays: 20,
        createdAt: new Date(),
      } as any;
    }
    return undefined;
  }, [students, authUser]);
  const studentRecords = attendanceRecords
    .filter(r => r.studentId === currentStudent?.studentId)
    .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

  const [filterMonth, setFilterMonth] = useState('');

  const filteredRecords = studentRecords.filter(record => {
    if (!filterMonth) return true;
    return record.date.startsWith(filterMonth);
  });

  const getAttendanceIcon = (percentage: number) => {
    if (percentage === 100) return <CheckCircle className="h-5 w-5 text-green-500" />;
    if (percentage === 50) return <Clock className="h-5 w-5 text-yellow-500" />;
    return <XCircle className="h-5 w-5 text-red-500" />;
  };

  const getAttendanceStatus = (percentage: number) => {
    if (percentage === 100) return { text: 'Full Day', color: 'bg-green-500/10 text-green-600 border-green-500/20' };
    if (percentage === 50) return { text: 'Half Day', color: 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20' };
    return { text: 'Absent', color: 'bg-red-500/10 text-red-600 border-red-500/20' };
  };

  if (!currentStudent) {
    return <div className="text-foreground">Loading...</div>;
  }

  const summaryCards = [
    {
      title: 'Overall',
      value: `${currentStudent.totalAttendance}%`,
      color: 'text-foreground',
    },
    {
      title: 'Full Days',
      value: studentRecords.filter(r => r.attendancePercentage === 100).length,
      color: 'text-green-600',
    },
    {
      title: 'Half Days',
      value: studentRecords.filter(r => r.attendancePercentage === 50).length,
      color: 'text-yellow-600',
    },
    {
      title: 'Absent',
      value: currentStudent.totalDays - studentRecords.length,
      color: 'text-red-600',
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-foreground">Attendance History</h2>
        <div className="text-sm text-muted-foreground">
          Your complete attendance record
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {summaryCards.map((card, index) => (
          <div key={index} className="glass p-6 rounded-xl shadow-lg hover-glow transition-all duration-300 transform hover:scale-105">
            <div className="text-center">
              <div className={`text-2xl font-bold ${card.color}`}>{card.value}</div>
              <div className="text-sm text-muted-foreground">{card.title}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Filter */}
      <div className="glass p-4 rounded-xl flex items-center space-x-4 hover-glow transition-all duration-300">
        <Filter className="h-5 w-5 text-muted-foreground" />
        <input
          type="month"
          value={filterMonth}
          onChange={(e) => setFilterMonth(e.target.value)}
          className="px-3 py-2 bg-background border border-border rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent text-foreground"
        />
        {filterMonth && (
          <button
            onClick={() => setFilterMonth('')}
            className="text-sm text-primary hover:text-primary/80 transition-colors"
          >
            Clear Filter
          </button>
        )}
      </div>

      {/* Records List */}
      <div className="glass rounded-xl shadow-lg overflow-hidden hover-glow transition-all duration-300">
        <div className="px-6 py-4 border-b border-border">
          <h3 className="text-lg font-semibold text-foreground">
            Records ({filteredRecords.length})
          </h3>
        </div>
        
        {filteredRecords.length === 0 ? (
          <div className="p-8 text-center">
            <Calendar className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-muted-foreground">No attendance records found.</p>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {filteredRecords.map((record) => {
              const status = getAttendanceStatus(record.attendancePercentage);
              return (
                <div key={record.id} className="p-6 hover:bg-muted/50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      {getAttendanceIcon(record.attendancePercentage)}
                      <div>
                        <div className="text-lg font-semibold text-foreground">
                          {format(new Date(record.date), 'EEEE, MMMM d, yyyy')}
                        </div>
                        <div className="text-sm text-muted-foreground">
                          {record.checkIn && `Check-in: ${format(new Date(record.checkIn), 'h:mm a')}`}
                          {record.checkIn && record.checkOut && ' • '}
                          {record.checkOut && `Check-out: ${format(new Date(record.checkOut), 'h:mm a')}`}
                        </div>
                      </div>
                    </div>
                    <div className="text-right">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${status.color}`}>
                        {status.text}
                      </span>
                      <div className="text-sm text-muted-foreground mt-1">
                        {record.attendancePercentage}%
                      </div>
                    </div>
                  </div>
                  
                  {(record.location || record.deviceInfo) && (
                    <div className="mt-3 pt-3 border-t border-border">
                      <div className="text-xs text-muted-foreground space-y-1">
                        {record.location && (
                          <div>Location: {record.location.latitude.toFixed(4)}, {record.location.longitude.toFixed(4)}</div>
                        )}
                        {record.deviceInfo && (
                          <div>Device: {record.deviceInfo.split(' ')[0]}</div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};