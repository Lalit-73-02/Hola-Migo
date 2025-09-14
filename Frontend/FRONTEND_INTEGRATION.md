# Frontend-Backend Integration Guide

This guide will help you connect your React frontend to the new SQL backend.

## 🔗 Quick Setup

### 1. Update Frontend API Configuration

Create or update your API configuration file:

```typescript
// src/lib/api.ts
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

export const api = {
  baseURL: API_BASE_URL,
  
  // Auth endpoints
  auth: {
    login: `${API_BASE_URL}/auth/login`,
    register: `${API_BASE_URL}/auth/register`,
    me: `${API_BASE_URL}/auth/me`,
    profile: `${API_BASE_URL}/auth/profile`,
    changePassword: `${API_BASE_URL}/auth/change-password`
  },
  
  // Attendance endpoints
  attendance: {
    checkIn: `${API_BASE_URL}/attendance/check-in`,
    checkOut: `${API_BASE_URL}/attendance/check-out`,
    student: (id: string) => `${API_BASE_URL}/attendance/student/${id}`,
    reports: `${API_BASE_URL}/attendance/reports`
  },
  
  // QR Code endpoints
  qr: {
    generate: `${API_BASE_URL}/qr/generate`,
    active: `${API_BASE_URL}/qr/active`,
    deactivate: (id: string) => `${API_BASE_URL}/qr/${id}/deactivate`
  },
  
  // Leave endpoints
  leave: {
    apply: `${API_BASE_URL}/leave/apply`,
    student: (id: string) => `${API_BASE_URL}/leave/student/${id}`,
    pending: `${API_BASE_URL}/leave/pending`,
    review: (id: string) => `${API_BASE_URL}/leave/${id}/review`
  },
  
  // Analytics endpoints
  analytics: {
    dashboard: `${API_BASE_URL}/analytics/dashboard`,
    attendance: `${API_BASE_URL}/analytics/attendance`,
    export: `${API_BASE_URL}/analytics/export`
  }
};
```

### 2. Update Authentication Hook

Update your `useAuth.tsx` hook to work with the new backend:

```typescript
// src/hooks/useAuth.tsx
import { useState, useEffect, createContext, useContext } from 'react';
import { api } from '@/lib/api';

interface User {
  id: number;
  name: string;
  email: string;
  role: 'admin' | 'student';
  studentId?: string;
  department?: string;
  year?: number;
  phoneNumber?: string;
  lastLoginAt?: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (email: string, password: string) => Promise<void>;
  register: (userData: any) => Promise<void>;
  logout: () => void;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      fetchUser();
    } else {
      setLoading(false);
    }
  }, [token]);

  const fetchUser = async () => {
    try {
      const response = await fetch(api.auth.me, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setUser(data.data.user);
      } else {
        // Token is invalid, clear it
        localStorage.removeItem('token');
        setToken(null);
        setUser(null);
      }
    } catch (error) {
      console.error('Error fetching user:', error);
      localStorage.removeItem('token');
      setToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email: string, password: string) => {
    try {
      const response = await fetch(api.auth.login, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Login failed');
      }

      setUser(data.data.user);
      setToken(data.data.token);
      localStorage.setItem('token', data.data.token);
    } catch (error) {
      throw error;
    }
  };

  const register = async (userData: any) => {
    try {
      const response = await fetch(api.auth.register, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(userData)
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Registration failed');
      }

      setUser(data.data.user);
      setToken(data.data.token);
      localStorage.setItem('token', data.data.token);
    } catch (error) {
      throw error;
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
  };

  return (
    <AuthContext.Provider value={{ user, token, login, register, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
```

### 3. Update API Service Functions

Create service functions for API calls:

```typescript
// src/services/api.ts
import { api } from '@/lib/api';

// Helper function for API calls
const apiCall = async (url: string, options: RequestInit = {}) => {
  const token = localStorage.getItem('token');
  
  const config: RequestInit = {
    headers: {
      'Content-Type': 'application/json',
      ...(token && { 'Authorization': `Bearer ${token}` }),
      ...options.headers
    },
    ...options
  };

  const response = await fetch(url, config);
  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || 'API request failed');
  }

  return data;
};

// Attendance services
export const attendanceService = {
  checkIn: async (qrCode: string, location?: { lat: number; lng: number }) => {
    return apiCall(api.attendance.checkIn, {
      method: 'POST',
      body: JSON.stringify({ qrCode, location })
    });
  },

  checkOut: async (qrCode: string, location?: { lat: number; lng: number }) => {
    return apiCall(api.attendance.checkOut, {
      method: 'POST',
      body: JSON.stringify({ qrCode, location })
    });
  },

  getStudentAttendance: async (studentId: string) => {
    return apiCall(api.attendance.student(studentId));
  },

  getReports: async (filters?: any) => {
    const params = new URLSearchParams(filters);
    return apiCall(`${api.attendance.reports}?${params}`);
  }
};

// QR Code services
export const qrService = {
  generate: async (data: { sessionType: 'check-in' | 'check-out'; location?: any }) => {
    return apiCall(api.qr.generate, {
      method: 'POST',
      body: JSON.stringify(data)
    });
  },

  getActive: async () => {
    return apiCall(api.qr.active);
  },

  deactivate: async (id: string) => {
    return apiCall(api.qr.deactivate(id), {
      method: 'PUT'
    });
  }
};

// Leave services
export const leaveService = {
  apply: async (data: { startDate: string; endDate: string; reason: string }) => {
    return apiCall(api.leave.apply, {
      method: 'POST',
      body: JSON.stringify(data)
    });
  },

  getStudentLeaves: async (studentId: string) => {
    return apiCall(api.leave.student(studentId));
  },

  getPending: async () => {
    return apiCall(api.leave.pending);
  },

  review: async (id: string, data: { status: 'approved' | 'rejected'; comments?: string }) => {
    return apiCall(api.leave.review(id), {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }
};

// Analytics services
export const analyticsService = {
  getDashboard: async () => {
    return apiCall(api.analytics.dashboard);
  },

  getAttendanceAnalytics: async (filters?: any) => {
    const params = new URLSearchParams(filters);
    return apiCall(`${api.analytics.attendance}?${params}`);
  },

  exportReports: async (format: 'excel' | 'pdf', filters?: any) => {
    const params = new URLSearchParams({ format, ...filters });
    return apiCall(`${api.analytics.export}?${params}`);
  }
};
```

### 4. Environment Variables

Create a `.env` file in your frontend root:

```env
VITE_API_URL=http://localhost:5000/api
```

### 5. Update Components

Update your components to use the new API services. For example:

```typescript
// Example: QR Scanner component
import { qrService } from '@/services/api';
import { useAuth } from '@/hooks/useAuth';

export const QRScanner = () => {
  const { user } = useAuth();
  const [scanning, setScanning] = useState(false);

  const handleScan = async (qrCode: string) => {
    try {
      setScanning(true);
      await qrService.checkIn(qrCode);
      // Show success message
    } catch (error) {
      // Show error message
    } finally {
      setScanning(false);
    }
  };

  // ... rest of component
};
```

## 🚀 Getting Started

1. **Start the Backend:**
   ```bash
   cd backend
   npm install
   cp env.example .env
   # Edit .env with your database credentials
   npm run setup
   npm run dev
   ```

2. **Update Frontend:**
   ```bash
   # In your frontend directory
   npm install
   # Update your API configuration as shown above
   npm run dev
   ```

3. **Test the Integration:**
   - Backend should be running on `http://localhost:5000`
   - Frontend should be running on `http://localhost:5173`
   - Test login with the default admin credentials

## 🔧 Common Issues & Solutions

### CORS Errors
Make sure your backend CORS configuration includes your frontend URL:
```env
CORS_ORIGIN=http://localhost:5173
```

### Database Connection Issues
- Ensure MySQL/PostgreSQL is running
- Check database credentials in `.env`
- Verify database exists: `CREATE DATABASE attendo;`

### Authentication Issues
- Check JWT secret in backend `.env`
- Ensure token is being sent in Authorization header
- Verify user exists in database

## 📝 API Response Format

All API responses follow this format:
```json
{
  "success": true,
  "data": {
    // Response data
  }
}
```

Error responses:
```json
{
  "success": false,
  "error": "Error message"
}
```

## 🔐 Security Notes

- Always use HTTPS in production
- Store JWT tokens securely
- Implement proper error handling
- Validate all user inputs
- Use environment variables for sensitive data

## 📞 Support

If you encounter any issues:
1. Check the backend logs for errors
2. Verify database connection
3. Test API endpoints with Postman/curl
4. Check browser network tab for failed requests
