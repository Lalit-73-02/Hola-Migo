import React, { useState } from 'react';
import { Download, FileText, Filter, Calendar } from 'lucide-react';
import { storage } from '../../utils/storage';
import { exportToPDF, exportToExcel } from '../../utils/exportUtils';
import { format } from 'date-fns';

export const AttendanceReports: React.FC = () => {
  const [dateFilter, setDateFilter] = useState({
    startDate: '',
    endDate: '',
  });
  const [departmentFilter, setDepartmentFilter] = useState('');

  const students = storage.getStudents();
  const attendanceRecords = storage.getAttendanceRecords();

  const filteredRecords = attendanceRecords.filter(record => {
    let matches = true;

    if (dateFilter.startDate && dateFilter.endDate) {
      const recordDate = new Date(record.date);
      const startDate = new Date(dateFilter.startDate);
      const endDate = new Date(dateFilter.endDate);
      matches = matches && recordDate >= startDate && recordDate <= endDate;
    }

    if (departmentFilter) {
      const student = students.find(s => s.studentId === record.studentId);
      matches = matches && student?.department === departmentFilter;
    }

    return matches;
  });

  const handleExportPDF = () => {
    exportToPDF(filteredRecords, students);
  };

  const handleExportExcel = () => {
    exportToExcel(filteredRecords, students);
  };

  const departments = [...new Set(students.map(s => s.department))];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-foreground">Attendance Reports</h2>
        <div className="flex space-x-3">
          <button
            onClick={handleExportPDF}
            className="flex items-center space-x-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors hover-glow"
          >
            <FileText className="h-4 w-4" />
            <span>Export PDF</span>
          </button>
          <button
            onClick={handleExportExcel}
            className="flex items-center space-x-2 px-4 py-2 bg-accent text-accent-foreground rounded-lg hover:bg-accent/90 transition-colors hover-glow"
          >
            <Download className="h-4 w-4" />
            <span>Export Excel</span>
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="rounded-lg p-6 glass hover-glow">
        <div className="flex items-center space-x-4 mb-4">
          <Filter className="h-5 w-5 text-muted-foreground" />
          <h3 className="text-lg font-semibold text-foreground">Filters</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-foreground mb-1">
              Start Date
            </label>
            <input
              type="date"
              value={dateFilter.startDate}
              onChange={(e) => setDateFilter({ ...dateFilter, startDate: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent bg-background text-foreground"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-foreground mb-1">
              End Date
            </label>
            <input
              type="date"
              value={dateFilter.endDate}
              onChange={(e) => setDateFilter({ ...dateFilter, endDate: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent bg-background text-foreground"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-foreground mb-1">
              Department
            </label>
            <select
              value={departmentFilter}
              onChange={(e) => setDepartmentFilter(e.target.value)}
              className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent bg-background text-foreground"
            >
              <option value="">All Departments</option>
              {departments.map(dept => (
                <option key={dept} value={dept}>{dept}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Reports Table */}
      <div className="rounded-lg shadow overflow-hidden glass hover-glow">
        <div className="px-6 py-4 border-b border-border/50">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-foreground">
              Attendance Records ({filteredRecords.length})
            </h3>
            <div className="flex items-center space-x-2 text-sm text-muted-foreground">
              <Calendar className="h-4 w-4" />
              <span>Generated on {format(new Date(), 'PPP')}</span>
            </div>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Date
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Student
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Department
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Check-in
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Check-out
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Attendance
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filteredRecords.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-muted-foreground">
                    No attendance records found for the selected filters.
                  </td>
                </tr>
              ) : (
                filteredRecords.map((record) => {
                  const student = students.find(s => s.studentId === record.studentId);
                  return (
                    <tr key={record.id} className="hover:bg-muted/30">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground">
                        {format(new Date(record.date), 'PPP')}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm font-medium text-foreground">
                          {student?.name || 'Unknown Student'}
                        </div>
                        <div className="text-sm text-muted-foreground">
                          ID: {record.studentId}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground">
                        {student?.department || 'N/A'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground">
                        {record.checkIn ? format(new Date(record.checkIn), 'pp') : (
                          <span className="text-muted-foreground">Not marked</span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground">
                        {record.checkOut ? format(new Date(record.checkOut), 'pp') : (
                          <span className="text-muted-foreground">Not marked</span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                            record.attendancePercentage === 100
                              ? 'bg-green-100 text-green-800'
                              : record.attendancePercentage === 50
                              ? 'bg-yellow-100 text-yellow-800'
                              : 'bg-red-100 text-red-800'
                          }`}>
                            {record.attendancePercentage}%
                          </span>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};