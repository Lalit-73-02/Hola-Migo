import React, { useState } from 'react';
import { Send, Calendar, FileText, Clock, CheckCircle, XCircle } from 'lucide-react';
import { storage } from '../../utils/storage';
import { LeaveApplication as LeaveApplicationType } from '../../types';
import { format } from 'date-fns';
import { useAuth } from '@/hooks/useAuth';

export const LeaveApplication: React.FC = () => {
  const { user: authUser } = useAuth();
  const students = storage.getStudents();
  const leaveApplications = storage.getLeaveApplications();
  
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
  const studentApplications = leaveApplications
    .filter(app => app.studentId === currentStudent?.studentId)
    .sort((a, b) => new Date(b.appliedAt).getTime() - new Date(a.appliedAt).getTime());

  const [formData, setFormData] = useState({
    startDate: '',
    endDate: '',
    reason: '',
  });
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentStudent) return;

    setSubmitting(true);

    const newApplication: LeaveApplicationType = {
      id: Math.random().toString(36).substr(2, 9),
      studentId: currentStudent.studentId,
      studentName: currentStudent.name,
      startDate: formData.startDate,
      endDate: formData.endDate,
      reason: formData.reason,
      status: 'pending',
      appliedAt: new Date(),
    };

    const updatedApplications = [...leaveApplications, newApplication];
    storage.setLeaveApplications(updatedApplications);

    // Reset form
    setFormData({ startDate: '', endDate: '', reason: '' });
    setSubmitting(false);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'approved':
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'rejected':
        return <XCircle className="h-5 w-5 text-red-500" />;
      case 'pending':
        return <Clock className="h-5 w-5 text-yellow-500" />;
      default:
        return <Clock className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'approved':
        return 'bg-green-500/10 text-green-600 border-green-500/20';
      case 'rejected':
        return 'bg-red-500/10 text-red-600 border-red-500/20';
      case 'pending':
        return 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20';
      default:
        return 'bg-muted text-muted-foreground border-border';
    }
  };

  if (!currentStudent) {
    return <div className="text-foreground">Loading...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-foreground">Leave Application</h2>
        <div className="text-sm text-muted-foreground">
          Apply for leave and track your applications
        </div>
      </div>

      {/* Application Form */}
      <div className="glass p-6 rounded-xl shadow-lg hover-glow transition-all duration-300">
        <h3 className="text-lg font-semibold text-foreground mb-4">Apply for Leave</h3>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-foreground mb-1">
                Start Date
              </label>
              <input
                type="date"
                value={formData.startDate}
                onChange={(e) => setFormData({ ...formData, startDate: e.target.value })}
                className="w-full px-3 py-2 bg-background border border-border rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent text-foreground"
                required
                min={new Date().toISOString().split('T')[0]}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-foreground mb-1">
                End Date
              </label>
              <input
                type="date"
                value={formData.endDate}
                onChange={(e) => setFormData({ ...formData, endDate: e.target.value })}
                className="w-full px-3 py-2 bg-background border border-border rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent text-foreground"
                required
                min={formData.startDate || new Date().toISOString().split('T')[0]}
              />
            </div>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-foreground mb-1">
              Reason for Leave
            </label>
            <textarea
              value={formData.reason}
              onChange={(e) => setFormData({ ...formData, reason: e.target.value })}
              rows={4}
              className="w-full px-3 py-2 bg-background border border-border rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent text-foreground"
              placeholder="Please provide a detailed reason for your leave application..."
              required
            />
          </div>
          
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={submitting}
              className="flex items-center space-x-2 px-6 py-2 bg-primary text-primary-foreground rounded-xl hover:bg-primary/90 focus:ring-4 focus:ring-primary/20 transition-all duration-300 disabled:opacity-50 hover-glow"
            >
              <Send className="h-4 w-4" />
              <span>{submitting ? 'Submitting...' : 'Submit Application'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Applications History */}
      <div className="glass rounded-xl shadow-lg hover-glow transition-all duration-300">
        <div className="px-6 py-4 border-b border-border">
          <h3 className="text-lg font-semibold text-foreground">
            Your Applications ({studentApplications.length})
          </h3>
        </div>
        
        {studentApplications.length === 0 ? (
          <div className="p-8 text-center">
            <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-muted-foreground">No leave applications found.</p>
            <p className="text-sm text-muted-foreground">Submit your first application using the form above.</p>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {studentApplications.map((application) => (
              <div key={application.id} className="p-6 hover:bg-muted/50 transition-colors">
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-4">
                    {getStatusIcon(application.status)}
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <h4 className="text-lg font-semibold text-foreground">
                          Leave Application
                        </h4>
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getStatusColor(application.status)}`}>
                          {application.status}
                        </span>
                      </div>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3 text-sm text-muted-foreground">
                        <div>
                          <span className="font-medium text-foreground">Start Date:</span>
                          <div>{format(new Date(application.startDate), 'PPP')}</div>
                        </div>
                        <div>
                          <span className="font-medium text-foreground">End Date:</span>
                          <div>{format(new Date(application.endDate), 'PPP')}</div>
                        </div>
                        <div>
                          <span className="font-medium text-foreground">Applied On:</span>
                          <div>{format(new Date(application.appliedAt), 'PPP')}</div>
                        </div>
                        {application.reviewedAt && (
                          <div>
                            <span className="font-medium text-foreground">Reviewed On:</span>
                            <div>{format(new Date(application.reviewedAt), 'PPP')}</div>
                          </div>
                        )}
                      </div>
                      
                      <div>
                        <span className="font-medium text-foreground">Reason:</span>
                        <p className="mt-1 text-muted-foreground bg-muted p-3 rounded-lg">
                          {application.reason}
                        </p>
                      </div>
                      
                      {application.reviewedBy && (
                        <div className="mt-3 text-sm text-muted-foreground">
                          Reviewed by {application.reviewedBy}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};