export interface User {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'student';
  studentId?: string;
  deviceId?: string;
  lastLoginDevice?: string;
  fingerprintId?: string;
  createdAt: Date;
}

export interface Student extends User {
  studentId: string;
  department: string;
  year: number;
  phoneNumber: string;
  totalAttendance: number;
  presentDays: number;
  totalDays: number;
}

export interface AttendanceRecord {
  id: string;
  studentId: string;
  date: string;
  checkIn?: Date;
  checkOut?: Date;
  attendancePercentage: number;
  location?: {
    latitude: number;
    longitude: number;
  };
  deviceInfo?: string;
  qrCodeId?: string;
}

export interface QRCode {
  id: string;
  code: string;
  generatedAt: Date;
  expiresAt: Date;
  isActive: boolean;
  sessionType: 'check-in' | 'check-out';
  location?: {
    latitude: number;
    longitude: number;
    radius: number;
  };
}

export interface LeaveApplication {
  id: string;
  studentId: string;
  studentName: string;
  startDate: string;
  endDate: string;
  reason: string;
  status: 'pending' | 'approved' | 'rejected';
  appliedAt: Date;
  reviewedAt?: Date;
  reviewedBy?: string;
}

export interface Session {
  userId: string;
  deviceId: string;
  loginTime: Date;
  lastActivity: Date;
  isActive: boolean;
}

