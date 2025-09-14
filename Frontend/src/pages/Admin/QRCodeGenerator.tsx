import React, { useState, useEffect } from 'react';
import { QrCode, MapPin, Clock, RefreshCw } from 'lucide-react';
import { generateQRCode, validateQRCode } from '../../utils/qrUtils';
import { storage } from '../../utils/storage';
import { QRCode as QRCodeType } from '../../types';

export const QRCodeGenerator: React.FC = () => {
  const [activeQR, setActiveQR] = useState<QRCodeType | null>(null);
  const [sessionType, setSessionType] = useState<'check-in' | 'check-out'>('check-in');
  const [useLocation, setUseLocation] = useState(true);
  const [location, setLocation] = useState<{ latitude: number; longitude: number; radius: number }>({
    latitude: 40.7128,
    longitude: -74.0060,
    radius: 100,
  });
  const [generating, setGenerating] = useState(false);
  const [timeLeft, setTimeLeft] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      if (activeQR && validateQRCode(activeQR)) {
        const now = new Date().getTime();
        const expiresAt = new Date(activeQR.expiresAt).getTime();
        setTimeLeft(Math.max(0, expiresAt - now));
      } else {
        setTimeLeft(0);
        if (activeQR) {
          setActiveQR(null);
        }
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [activeQR]);

  const handleGenerateQR = async () => {
    setGenerating(true);
    try {
      const qrLocation = useLocation ? location : undefined;
      const newQR = await generateQRCode(sessionType, qrLocation);
      
      // Save to storage
      const qrCodes = storage.getQRCodes();
      // Deactivate previous QR codes
      const updatedQRCodes = qrCodes.map(qr => ({ ...qr, isActive: false }));
      updatedQRCodes.push(newQR);
      storage.setQRCodes(updatedQRCodes);
      
      setActiveQR(newQR);
    } catch (error) {
      console.error('Failed to generate QR code:', error);
    } finally {
      setGenerating(false);
    }
  };

  const getCurrentLocation = () => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          setLocation({
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
            radius: 100,
          });
        },
        (error) => {
          console.error('Geolocation error:', error);
        }
      );
    }
  };

  const formatTime = (ms: number) => {
    const minutes = Math.floor(ms / (1000 * 60));
    const seconds = Math.floor((ms % (1000 * 60)) / 1000);
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-foreground">QR Code Generator</h2>
        <div className="text-sm text-muted-foreground">
          Generate secure QR codes for attendance marking
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* QR Generation Controls */}
        <div className="rounded-lg p-6 space-y-6 glass">
          <h3 className="text-lg font-semibold text-foreground">Generation Settings</h3>
          
          {/* Session Type */}
          <div>
            <label className="block text-sm font-medium text-foreground mb-2">
              Session Type
            </label>
            <div className="flex rounded-lg border overflow-hidden">
              <button
                onClick={() => setSessionType('check-in')}
                className={`flex-1 px-4 py-2 text-sm font-medium ${
                  sessionType === 'check-in'
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-background text-foreground hover:bg-muted'
                }`}
              >
                Check-in
              </button>
              <button
                onClick={() => setSessionType('check-out')}
                className={`flex-1 px-4 py-2 text-sm font-medium ${
                  sessionType === 'check-out'
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-background text-foreground hover:bg-muted'
                }`}
              >
                Check-out
              </button>
            </div>
          </div>

          {/* Location Settings */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="block text-sm font-medium text-foreground">
                Location Restriction
              </label>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={useLocation}
                  onChange={(e) => setUseLocation(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-muted peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary/30 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-background after:border after:border-border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>
            
            {useLocation && (
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">Latitude</label>
                    <input
                      type="number"
                      step="any"
                      value={location.latitude}
                      onChange={(e) => setLocation({ ...location, latitude: parseFloat(e.target.value) })}
                      className="w-full px-3 py-2 text-sm border rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent bg-background text-foreground"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">Longitude</label>
                    <input
                      type="number"
                      step="any"
                      value={location.longitude}
                      onChange={(e) => setLocation({ ...location, longitude: parseFloat(e.target.value) })}
                      className="w-full px-3 py-2 text-sm border rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent bg-background text-foreground"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-xs text-muted-foreground mb-1">Radius (meters)</label>
                  <input
                    type="number"
                    value={location.radius}
                    onChange={(e) => setLocation({ ...location, radius: parseInt(e.target.value) })}
                    className="w-full px-3 py-2 text-sm border rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent bg-background text-foreground"
                  />
                </div>
                <button
                  onClick={getCurrentLocation}
                  className="flex items-center space-x-2 px-3 py-2 bg-muted text-foreground rounded-lg hover:bg-muted/80 transition-colors text-sm"
                >
                  <MapPin className="h-4 w-4" />
                  <span>Use Current Location</span>
                </button>
              </div>
            )}
          </div>

          <button
            onClick={handleGenerateQR}
            disabled={generating}
            className="w-full flex items-center justify-center space-x-2 px-4 py-3 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 focus:ring-4 focus:ring-primary/20 transition-colors disabled:opacity-50"
          >
            {generating ? (
              <RefreshCw className="h-5 w-5 animate-spin" />
            ) : (
              <QrCode className="h-5 w-5" />
            )}
            <span>{generating ? 'Generating...' : 'Generate New QR Code'}</span>
          </button>
        </div>

        {/* QR Display */}
        <div className="rounded-lg p-6 text-center space-y-4 glass">
          {activeQR ? (
            <>
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-foreground">
                  Active QR Code
                </h3>
                <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                  <Clock className="h-4 w-4" />
                  <span>{formatTime(timeLeft)}</span>
                </div>
              </div>
              
              <div className="bg-background p-4 rounded-lg">
                <img
                  src={activeQR.code}
                  alt="QR Code"
                  className="mx-auto w-64 h-64"
                />
              </div>
              
              <div className="text-sm space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Type:</span>
                  <span className="font-medium capitalize">{activeQR.sessionType}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Generated:</span>
                  <span className="font-medium">
                    {new Date(activeQR.generatedAt).toLocaleTimeString()}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Expires:</span>
                  <span className="font-medium">
                    {new Date(activeQR.expiresAt).toLocaleTimeString()}
                  </span>
                </div>
                {activeQR.location && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Location:</span>
                    <span className="font-medium">
                      {activeQR.location.latitude.toFixed(4)}, {activeQR.location.longitude.toFixed(4)}
                    </span>
                  </div>
                )}
              </div>
              
              {timeLeft <= 300000 && ( // 5 minutes warning
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
                  <p className="text-sm text-yellow-800">
                    ⚠️ QR Code expires in {formatTime(timeLeft)}
                  </p>
                </div>
              )}
            </>
          ) : (
            <div className="py-16">
              <QrCode className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">No active QR code</p>
              <p className="text-sm text-muted-foreground/80">Generate a new QR code to get started</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};