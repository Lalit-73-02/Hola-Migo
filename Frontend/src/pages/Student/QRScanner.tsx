import React, { useState, useRef } from 'react';
import { Camera, MapPin, Wifi, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';
import { storage } from '../../utils/storage';
import { verifyLocation, verifyWiFi, decryptQRData } from '../../utils/security';
import { AttendanceRecord } from '../../types';

export const QRScanner: React.FC = () => {
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<{
    success: boolean;
    message: string;
    type?: 'check-in' | 'check-out';
  } | null>(null);
  const [location, setLocation] = useState<{ latitude: number; longitude: number } | null>(null);
  const [wifiStatus, setWifiStatus] = useState<boolean | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const currentUser = storage.getCurrentUser();
  const students = storage.getStudents();
  const currentStudent = students.find(s => s.id === currentUser?.id);

  React.useEffect(() => {
    // Get current location
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          setLocation({
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
          });
        },
        (error) => {
          console.error('Geolocation error:', error);
        }
      );
    }

    // Check WiFi status
    verifyWiFi().then(setWifiStatus);
  }, []);

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file || !currentStudent) return;

    setScanning(true);
    setResult(null);

    try {
      // In a real implementation, you would use a QR code reading library
      // For demo purposes, we'll simulate QR code reading
      const reader = new FileReader();
      reader.onload = async (e) => {
        try {
          // Simulate QR code data extraction
          const qrData = 'demo_qr_data_' + Date.now(); // This would be the actual QR data
          await processQRCode(qrData);
        } catch (error) {
          setResult({
            success: false,
            message: 'Failed to read QR code. Please try again.',
          });
        } finally {
          setScanning(false);
        }
      };
      reader.readAsDataURL(file);
    } catch (error) {
      setResult({
        success: false,
        message: 'Failed to process the image. Please try again.',
      });
      setScanning(false);
    }
  };

  const processQRCode = async (qrData: string) => {
    if (!currentStudent || !location) {
      setResult({
        success: false,
        message: 'Unable to verify location. Please enable location services.',
      });
      return;
    }

    // For demo purposes, simulate QR code validation
    const sessionType: 'check-in' | 'check-out' = Math.random() > 0.5 ? 'check-in' : 'check-out';
    const campusLocation = { latitude: 40.7128, longitude: -74.0060 }; // Mock campus location

    // Verify location (within 100m of campus)
    const locationValid = verifyLocation(
      location.latitude,
      location.longitude,
      campusLocation.latitude,
      campusLocation.longitude,
      100
    );

    if (!locationValid) {
      setResult({
        success: false,
        message: 'You must be on campus to mark attendance.',
      });
      return;
    }

    // Verify WiFi (mock check)
    if (!wifiStatus) {
      setResult({
        success: false,
        message: 'Please connect to campus WiFi to mark attendance.',
      });
      return;
    }

    // Check if already marked for today
    const today = new Date().toISOString().split('T')[0];
    const attendanceRecords = storage.getAttendanceRecords();
    const todayRecord = attendanceRecords.find(
      r => r.studentId === currentStudent.studentId && r.date === today
    );

    let updatedRecord: AttendanceRecord;

    if (todayRecord) {
      // Update existing record
      if (sessionType === 'check-in' && todayRecord.checkIn) {
        setResult({
          success: false,
          message: 'You have already checked in today.',
        });
        return;
      }

      if (sessionType === 'check-out' && todayRecord.checkOut) {
        setResult({
          success: false,
          message: 'You have already checked out today.',
        });
        return;
      }

      if (sessionType === 'check-out' && !todayRecord.checkIn) {
        setResult({
          success: false,
          message: 'You must check in first before checking out.',
        });
        return;
      }

      updatedRecord = {
        ...todayRecord,
        [sessionType === 'check-in' ? 'checkIn' : 'checkOut']: new Date(),
        attendancePercentage: sessionType === 'check-in' ? 50 : 100,
        location,
        deviceInfo: navigator.userAgent,
      };

      const updatedRecords = attendanceRecords.map(r =>
        r.id === todayRecord.id ? updatedRecord : r
      );
      storage.setAttendanceRecords(updatedRecords);
    } else {
      // Create new record
      if (sessionType === 'check-out') {
        setResult({
          success: false,
          message: 'You must check in first before checking out.',
        });
        return;
      }

      updatedRecord = {
        id: Math.random().toString(36).substr(2, 9),
        studentId: currentStudent.studentId,
        date: today,
        checkIn: new Date(),
        attendancePercentage: 50,
        location,
        deviceInfo: navigator.userAgent,
      };

      storage.setAttendanceRecords([...attendanceRecords, updatedRecord]);
    }

    // Update student's overall attendance
    const updatedStudents = students.map(s => {
      if (s.id === currentStudent.id) {
        const newPresentDays = sessionType === 'check-out' ? s.presentDays + 0.5 : s.presentDays + 0.5;
        const newTotalDays = s.totalDays || 20; // Mock total days
        return {
          ...s,
          presentDays: newPresentDays,
          totalDays: newTotalDays,
          totalAttendance: Math.round((newPresentDays / newTotalDays) * 100),
        };
      }
      return s;
    });

    storage.setStudents(updatedStudents);

    setResult({
      success: true,
      message: `Successfully ${sessionType === 'check-in' ? 'checked in' : 'checked out'}! Attendance: ${updatedRecord.attendancePercentage}%`,
      type: sessionType,
    });
  };

  const getLocationStatus = () => {
    if (!location) return { icon: AlertTriangle, color: 'text-yellow-500', text: 'Getting location...' };
    return { icon: MapPin, color: 'text-green-500', text: 'Location verified' };
  };

  const getWiFiStatus = () => {
    if (wifiStatus === null) return { icon: AlertTriangle, color: 'text-yellow-500', text: 'Checking WiFi...' };
    if (wifiStatus) return { icon: Wifi, color: 'text-green-500', text: 'Campus WiFi connected' };
    return { icon: XCircle, color: 'text-red-500', text: 'Not on campus WiFi' };
  };

  const locationStatus = getLocationStatus();
  const wifiStatusInfo = getWiFiStatus();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-foreground">QR Code Scanner</h2>
        <div className="text-sm text-muted-foreground">
          Scan QR codes to mark attendance
        </div>
      </div>

      {/* Security Status */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="glass p-4 rounded-xl flex items-center space-x-3 hover-glow transition-all duration-300">
          <locationStatus.icon className={`h-5 w-5 ${locationStatus.color}`} />
          <span className="text-sm font-medium text-foreground">{locationStatus.text}</span>
        </div>
        <div className="glass p-4 rounded-xl flex items-center space-x-3 hover-glow transition-all duration-300">
          <wifiStatusInfo.icon className={`h-5 w-5 ${wifiStatusInfo.color}`} />
          <span className="text-sm font-medium text-foreground">{wifiStatusInfo.text}</span>
        </div>
      </div>

      {/* Scanner Interface */}
      <div className="glass p-8 rounded-xl text-center hover-glow transition-all duration-300 transform hover:scale-105">
        <div className="space-y-4">
          <Camera className="h-16 w-16 text-muted-foreground mx-auto" />
          <h3 className="text-lg font-semibold text-foreground">
            Upload QR Code Image
          </h3>
          <p className="text-muted-foreground">
            Take a photo of the QR code or upload an image to mark your attendance
          </p>
          
          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            capture="environment"
            onChange={handleFileUpload}
            className="hidden"
          />
          
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={scanning || !location || !wifiStatus}
            className="inline-flex items-center space-x-2 px-6 py-3 bg-primary text-primary-foreground rounded-xl hover:bg-primary/90 focus:ring-4 focus:ring-primary/20 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed hover-glow"
          >
            <Camera className="h-5 w-5" />
            <span>{scanning ? 'Processing...' : 'Take Photo / Upload Image'}</span>
          </button>
          
          {(!location || !wifiStatus) && (
            <p className="text-sm text-destructive mt-2">
              Please ensure location and WiFi permissions are enabled
            </p>
          )}
        </div>
      </div>

      {/* Result */}
      {result && (
        <div className={`glass p-4 rounded-xl border hover-glow transition-all duration-300 ${
          result.success 
            ? 'border-green-500/20 bg-green-500/5' 
            : 'border-red-500/20 bg-red-500/5'
        }`}>
          <div className="flex items-center space-x-3">
            {result.success ? (
              <CheckCircle className="h-6 w-6 text-green-600" />
            ) : (
              <XCircle className="h-6 w-6 text-red-600" />
            )}
            <div>
              <p className={`font-medium text-foreground`}>
                {result.success ? 'Success!' : 'Failed'}
              </p>
              <p className={`text-sm text-muted-foreground`}>
                {result.message}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Today's Status */}
      {currentStudent && (
        <div className="glass p-6 rounded-xl hover-glow transition-all duration-300 transform hover:scale-105">
          <h3 className="text-lg font-semibold text-foreground mb-4">Today's Status</h3>
          <div className="grid grid-cols-2 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-foreground">
                {currentStudent.totalAttendance}%
              </div>
              <div className="text-sm text-muted-foreground">Overall Attendance</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-foreground">
                {currentStudent.presentDays}/{currentStudent.totalDays}
              </div>
              <div className="text-sm text-muted-foreground">Days Present</div>
            </div>
          </div>
          
          {currentStudent.totalAttendance < 75 && (
            <div className="mt-4 glass border border-yellow-500/20 rounded-xl p-3 hover-glow transition-all duration-300">
              <p className="text-sm text-yellow-600">
                ⚠️ Your attendance is below 75%. Please maintain regular attendance.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};