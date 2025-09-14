import { User, Student, AttendanceRecord, QRCode, LeaveApplication, Session } from '../types';

class LocalStorageManager {
  private getItem<T>(key: string, defaultValue: T): T {
    try {
      const item = localStorage.getItem(key);
      return item ? JSON.parse(item) : defaultValue;
    } catch {
      return defaultValue;
    }
  }

  private setItem<T>(key: string, value: T): void {
    localStorage.setItem(key, JSON.stringify(value));
  }

  // Users
  getUsers(): User[] {
    return this.getItem('users', []);
  }

  setUsers(users: User[]): void {
    this.setItem('users', users);
  }

  // Students
  getStudents(): Student[] {
    return this.getItem('students', []);
  }

  setStudents(students: Student[]): void {
    this.setItem('students', students);
  }

  // Attendance Records
  getAttendanceRecords(): AttendanceRecord[] {
    return this.getItem('attendanceRecords', []);
  }

  setAttendanceRecords(records: AttendanceRecord[]): void {
    this.setItem('attendanceRecords', records);
  }

  // QR Codes
  getQRCodes(): QRCode[] {
    return this.getItem('qrCodes', []);
  }

  setQRCodes(qrCodes: QRCode[]): void {
    this.setItem('qrCodes', qrCodes);
  }

  // Leave Applications
  getLeaveApplications(): LeaveApplication[] {
    return this.getItem('leaveApplications', []);
  }

  setLeaveApplications(applications: LeaveApplication[]): void {
    this.setItem('leaveApplications', applications);
  }

  // Sessions
  getSessions(): Session[] {
    return this.getItem('sessions', []);
  }

  setSessions(sessions: Session[]): void {
    this.setItem('sessions', sessions);
  }

  // Current User
  getCurrentUser(): User | null {
    return this.getItem('currentUser', null);
  }

  setCurrentUser(user: User | null): void {
    this.setItem('currentUser', user);
  }
}

export const storage = new LocalStorageManager();

// Initialize demo data
export const initializeDemoData = () => {
  const users = storage.getUsers();
  if (users.length === 0) {
    const demoUsers: User[] = [
      {
        id: '1',
        name: 'Admin User',
        email: 'admin@college.edu',
        role: 'admin',
        createdAt: new Date(),
      },
      {
        id: '2',
        name: 'John Doe',
        email: 'john@student.edu',
        role: 'student',
        studentId: 'CS2021001',
        createdAt: new Date(),
      },
      {
        id: '3',
        name: 'Jane Smith',
        email: 'jane@student.edu',
        role: 'student',
        studentId: 'CS2021002',
        createdAt: new Date(),
      },
    ];

    const demoStudents: Student[] = [
      {
        id: '2',
        name: 'John Doe',
        email: 'john@student.edu',
        role: 'student',
        studentId: 'CS2021001',
        department: 'Computer Science',
        year: 3,
        phoneNumber: '+1234567890',
        totalAttendance: 85,
        presentDays: 17,
        totalDays: 20,
        createdAt: new Date(),
      },
      {
        id: '3',
        name: 'Jane Smith',
        email: 'jane@student.edu',
        role: 'student',
        studentId: 'CS2021002',
        department: 'Computer Science',
        year: 3,
        phoneNumber: '+1234567891',
        totalAttendance: 92,
        presentDays: 18,
        totalDays: 20,
        createdAt: new Date(),
      },
    ];

    storage.setUsers(demoUsers);
    storage.setStudents(demoStudents);
  }
};