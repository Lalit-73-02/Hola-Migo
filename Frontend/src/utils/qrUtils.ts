import QRCode from 'qrcode';
import { QRCode as QRCodeType } from '../types';
import { encryptQRData } from './security';

export const generateQRCode = async (
  sessionType: 'check-in' | 'check-out',
  location?: { latitude: number; longitude: number; radius: number }
): Promise<QRCodeType> => {
  const id = Math.random().toString(36).substr(2, 9);
  const generatedAt = new Date();
  const expiresAt = new Date(generatedAt.getTime() + 30 * 60 * 1000); // 30 minutes

  const qrData = {
    id,
    sessionType,
    generatedAt: generatedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    location,
  };

  const encryptedData = encryptQRData(JSON.stringify(qrData));
  const qrCodeDataURL = await QRCode.toDataURL(encryptedData, {
    width: 300,
    margin: 2,
    color: {
      dark: '#2563eb',
      light: '#ffffff',
    },
  });

  return {
    id,
    code: qrCodeDataURL,
    generatedAt,
    expiresAt,
    isActive: true,
    sessionType,
    location,
  };
};

export const validateQRCode = (qrCode: QRCodeType): boolean => {
  const now = new Date();
  return qrCode.isActive && now < qrCode.expiresAt;
};