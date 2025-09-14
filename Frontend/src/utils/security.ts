import { Session } from '../types';

// Device fingerprinting
export const generateDeviceId = (): string => {
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  ctx!.textBaseline = 'top';
  ctx!.font = '14px Arial';
  ctx!.fillText('Device fingerprint', 2, 2);
  
  const fingerprint = [
    navigator.userAgent,
    navigator.language,
    screen.width + 'x' + screen.height,
    new Date().getTimezoneOffset(),
    canvas.toDataURL()
  ].join('|');
  
  return btoa(fingerprint).slice(0, 32);
};

// Location verification
export const verifyLocation = (
  currentLat: number,
  currentLng: number,
  allowedLat: number,
  allowedLng: number,
  radiusMeters: number = 100
): boolean => {
  const R = 6371e3; // Earth's radius in meters
  const φ1 = currentLat * Math.PI / 180;
  const φ2 = allowedLat * Math.PI / 180;
  const Δφ = (allowedLat - currentLat) * Math.PI / 180;
  const Δλ = (allowedLng - currentLat) * Math.PI / 180;

  const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
            Math.cos(φ1) * Math.cos(φ2) *
            Math.sin(Δλ/2) * Math.sin(Δλ/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));

  const distance = R * c;
  return distance <= radiusMeters;
};

// WiFi verification (simplified - in real app would use network APIs)
export const verifyWiFi = (): Promise<boolean> => {
  return new Promise((resolve) => {
    // Mock WiFi check - in real implementation would check SSID
    // For demo, we'll assume user is on campus WiFi
    resolve(Math.random() > 0.3); // 70% success rate for demo
  });
};

// Session management
export const validateSession = (session: Session): boolean => {
  const now = new Date();
  const lastActivity = new Date(session.lastActivity);
  const inactiveTime = now.getTime() - lastActivity.getTime();
  const maxInactiveTime = 30 * 60 * 1000; // 30 minutes

  return session.isActive && inactiveTime < maxInactiveTime;
};

// QR Code security
export const encryptQRData = (data: string): string => {
  // Simple encryption for demo - in production use proper encryption
  return btoa(data + '|' + Date.now());
};

export const decryptQRData = (encryptedData: string): { data: string; timestamp: number } | null => {
  try {
    const decoded = atob(encryptedData);
    const [data, timestamp] = decoded.split('|');
    return { data, timestamp: parseInt(timestamp) };
  } catch {
    return null;
  }
};