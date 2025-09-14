import { useState, useEffect } from 'react';
import { useAuth } from './useAuth';

export interface AttendanceRecord {
  id: string;
  userId: string;
  timestamp: string;
  type: 'check-in' | 'check-out';
  location?: {
    latitude: number;
    longitude: number;
    address?: string;
  };
  notes?: string;
}

export function useAttendance() {
  const { user } = useAuth();
  const [records, setRecords] = useState<AttendanceRecord[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadAttendanceRecords();
  }, [user]);

  const loadAttendanceRecords = () => {
    const storedRecords = localStorage.getItem('attendo_attendance');
    const allRecords: AttendanceRecord[] = storedRecords ? JSON.parse(storedRecords) : [];
    
    if (user?.role === 'admin') {
      setRecords(allRecords);
    } else if (user) {
      setRecords(allRecords.filter(record => record.userId === user.id));
    }
  };

  const markAttendance = async (type: 'check-in' | 'check-out', notes?: string) => {
    if (!user) return { error: 'User not authenticated' };
    
    setLoading(true);
    
    try {
      // Get current location for geo-fencing
      const location = await getCurrentLocation();
      
      // Check if location is within allowed area (demo: 100m radius from office)
      const officeLocation = { latitude: 40.7128, longitude: -74.0060 }; // Example: NYC
      const distance = calculateDistance(
        location.latitude,
        location.longitude,
        officeLocation.latitude,
        officeLocation.longitude
      );
      
      if (distance > 0.1) { // 100 meters
        setLoading(false);
        return { error: 'You are not within the allowed location range' };
      }
      
      const newRecord: AttendanceRecord = {
        id: crypto.randomUUID(),
        userId: user.id,
        timestamp: new Date().toISOString(),
        type,
        location: {
          latitude: location.latitude,
          longitude: location.longitude,
          address: await getAddressFromCoords(location.latitude, location.longitude)
        },
        notes
      };
      
      const storedRecords = localStorage.getItem('attendo_attendance');
      const allRecords: AttendanceRecord[] = storedRecords ? JSON.parse(storedRecords) : [];
      allRecords.push(newRecord);
      
      localStorage.setItem('attendo_attendance', JSON.stringify(allRecords));
      loadAttendanceRecords();
      
      setLoading(false);
      return { success: true, record: newRecord };
    } catch (error) {
      setLoading(false);
      return { error: 'Failed to mark attendance' };
    }
  };

  const getCurrentLocation = (): Promise<{ latitude: number; longitude: number }> => {
    return new Promise((resolve, reject) => {
      if (!navigator.geolocation) {
        reject(new Error('Geolocation is not supported'));
        return;
      }
      
      navigator.geolocation.getCurrentPosition(
        position => {
          resolve({
            latitude: position.coords.latitude,
            longitude: position.coords.longitude
          });
        },
        error => reject(error),
        { enableHighAccuracy: true, timeout: 10000, maximumAge: 60000 }
      );
    });
  };

  const calculateDistance = (lat1: number, lon1: number, lat2: number, lon2: number) => {
    const R = 6371; // Earth's radius in km
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = 
      Math.sin(dLat/2) * Math.sin(dLat/2) +
      Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
      Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c; // Distance in km
  };

  const getAddressFromCoords = async (lat: number, lng: number): Promise<string> => {
    // In a real app, you'd use a geocoding service
    return `${lat.toFixed(4)}, ${lng.toFixed(4)}`;
  };

  const getTodayAttendance = () => {
    const today = new Date().toDateString();
    return records.filter(record => 
      new Date(record.timestamp).toDateString() === today
    );
  };

  const getAttendanceStats = () => {
    const totalDays = records.length > 0 ? 
      Math.ceil((Date.now() - new Date(records[0].timestamp).getTime()) / (1000 * 60 * 60 * 24)) : 0;
    const attendedDays = new Set(records.map(r => new Date(r.timestamp).toDateString())).size;
    const percentage = totalDays > 0 ? (attendedDays / totalDays) * 100 : 0;
    
    return {
      totalDays,
      attendedDays,
      percentage: Math.round(percentage),
      streak: calculateStreak()
    };
  };

  const calculateStreak = () => {
    // Simple streak calculation - consecutive days with attendance
    let streak = 0;
    const today = new Date();
    
    for (let i = 0; i < 30; i++) {
      const checkDate = new Date(today);
      checkDate.setDate(today.getDate() - i);
      const dateString = checkDate.toDateString();
      
      const hasAttendance = records.some(record => 
        new Date(record.timestamp).toDateString() === dateString
      );
      
      if (hasAttendance) {
        streak++;
      } else if (i > 0) {
        break;
      }
    }
    
    return streak;
  };

  return {
    records,
    loading,
    markAttendance,
    getTodayAttendance,
    getAttendanceStats
  };
}