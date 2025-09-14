export type Role = 'admin' | 'student';
export type Method = 'qr' | 'auto' | 'manual';

export type Student = {
  id: string;
  name: string;
  email: string;
  roll: string;
  className: string;
  avatarUrl?: string;
};

export type Session = {
  id: string;
  name: string;
  lat: number;
  lng: number;
  radiusMeters: number;
  startsAt: string;
  expiresAt: string;
  requireFence: boolean;
  token: string;
  createdBy: string; // admin id
};

export type Attendance = {
  id: string;
  studentId: string;
  sessionId?: string;
  type: 'check-in' | 'check-out';
  method: Method;
  timestamp: string;
  lat?: number;
  lng?: number;
  distanceMeters?: number;
  notes?: string;
};


