import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, User, Mail, Lock, UserCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useAuth } from '@/hooks/useAuth';
import { useToast } from '@/hooks/use-toast';

interface AuthDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function AuthDialog({ isOpen, onClose }: AuthDialogProps) {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    name: '',
    role: 'student' as 'admin' | 'student',
    adminPasskey: '',
    fingerprintId: ''
  });
  const [isScanning, setIsScanning] = useState(false);
  const [loading, setLoading] = useState(false);
  
  const { login, register } = useAuth();
  const { toast } = useToast();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      if (isLogin) {
        const result = await login(formData.email, formData.password);
        if ('error' in result) {
          toast({
            title: 'Login Failed',
            description: result.error,
            variant: 'destructive'
          });
        } else {
          toast({
            title: 'Welcome back!',
            description: `Logged in as ${result.user.name}`
          });
          onClose();
        }
      } else {
        if (formData.role === 'admin') {
          const expected = import.meta.env.VITE_ADMIN_PASSKEY || 'ADMIN-1234';
          if (!formData.adminPasskey || formData.adminPasskey !== expected) {
            toast({ title: 'Invalid Passkey', description: 'Admin passkey is incorrect.', variant: 'destructive' });
            return;
          }
        }

        if (formData.role === 'student' && !formData.fingerprintId) {
          toast({ title: 'Fingerprint Required', description: 'Please provide your fingerprint ID.', variant: 'destructive' });
          return;
        }

        const result = await register(formData.email, formData.password, formData.name, formData.role);
        if ('error' in result) {
          toast({
            title: 'Registration Failed',
            description: result.error,
            variant: 'destructive'
          });
        } else {
          toast({
            title: 'Account Created!',
            description: `Welcome, ${result.user.name}`
          });
          onClose();
        }
      }
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (field: string, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleScanFingerprint = async () => {
    try {
      setIsScanning(true);
      const apiBase = import.meta.env.VITE_API_BASE;
      if (!apiBase || !/^https:\/\//.test(apiBase)) {
        toast({ title: 'Backend URL not set', description: 'Set VITE_API_BASE to an HTTPS backend.', variant: 'destructive' });
        return;
      }
      if (!formData.email) {
        toast({ title: 'Enter email first', description: 'Email is required before scanning.', variant: 'destructive' });
        return;
      }
      // Try WebAuthn first
      if (!('PublicKeyCredential' in window)) {
        toast({ title: 'Biometrics not supported', description: 'Your browser/device does not support WebAuthn.', variant: 'destructive' });
        await new Promise((r) => setTimeout(r, 1200));
        const generatedId = `FP-${crypto.randomUUID().slice(0, 8)}`;
        setFormData(prev => ({ ...prev, fingerprintId: generatedId }));
        return;
      }
      const uvpa = await (window as any).PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.();
      if (!uvpa) {
        toast({ title: 'Platform authenticator unavailable', description: 'Enable screen lock and enroll biometrics.', variant: 'destructive' });
        return;
      }
      {
        // 1) Get options from backend
        const resp = await fetch(`${apiBase}/api/webauthn/register/options`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: formData.email, name: formData.name || 'Student' })
        });
        if (!resp.ok) throw new Error(`options ${resp.status}`);
        const { publicKey } = await resp.json();

        // Convert base64url strings to ArrayBuffers
        const toBuffer = (b64url: string) => Uint8Array.from(atob(b64url.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)).buffer;
        publicKey.challenge = toBuffer(publicKey.challenge);
        publicKey.user.id = toBuffer(publicKey.user.id);

        const credential: any = await navigator.credentials.create({ publicKey });
        if (!credential) throw new Error('no_credential');

        const attObj = (credential.response as any).attestationObject;
        const clientData = (credential.response as any).clientDataJSON;
        const rawId = credential.rawId;

        const toBase64Url = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');

        const verifyResp = await fetch(`${apiBase}/api/webauthn/register/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: formData.email,
            clientDataJSON: toBase64Url(clientData),
            attestationObject: toBase64Url(attObj),
            rawId: toBase64Url(rawId)
          })
        });
        const verifyJson = await verifyResp.json();
        if (!verifyResp.ok || !verifyJson.verified) throw new Error('verify_failed');
        setFormData(prev => ({ ...prev, fingerprintId: verifyJson.credentialId }));
        toast({ title: 'Biometric registered', description: 'Device credential captured' });
      }
    } finally {
      setIsScanning(false);
    }
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center">
        {/* Backdrop */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="absolute inset-0 bg-black/50 backdrop-blur-sm"
          onClick={onClose}
        />
        
        {/* Dialog */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          className="relative z-10 w-full max-w-md mx-4"
        >
          <Card className="glass hover-glow">
            <CardHeader className="text-center">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <UserCheck className="h-8 w-8 text-primary" />
                  <CardTitle className="text-2xl gradient-text">Attendo</CardTitle>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={onClose}
                  className="hover-glow"
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
              <CardDescription>
                {isLogin ? 'Sign in to your account' : 'Create your account'}
              </CardDescription>
            </CardHeader>
            
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-4">
                {!isLogin && (
                  <div className="space-y-2">
                    <Label htmlFor="name">Full Name</Label>
                    <div className="relative">
                      <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                      <Input
                        id="name"
                        type="text"
                        placeholder="Enter your name"
                        className="pl-10"
                        value={formData.name}
                        onChange={(e) => handleChange('name', e.target.value)}
                        required={!isLogin}
                      />
                    </div>
                  </div>
                )}
                
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                    <Input
                      id="email"
                      type="email"
                      placeholder="Enter your email"
                      className="pl-10"
                      value={formData.email}
                      onChange={(e) => handleChange('email', e.target.value)}
                      required
                    />
                  </div>
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                    <Input
                      id="password"
                      type="password"
                      placeholder="Enter your password"
                      className="pl-10"
                      value={formData.password}
                      onChange={(e) => handleChange('password', e.target.value)}
                      required
                    />
                  </div>
                </div>
                
                {!isLogin && (
                  <div className="space-y-2">
                    <Label htmlFor="role">Role</Label>
                    <Select
                      value={formData.role}
                      onValueChange={(value: 'admin' | 'student') => handleChange('role', value)}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select your role" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="student">Student</SelectItem>
                        <SelectItem value="admin">Admin</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                )}

                {!isLogin && formData.role === 'admin' && (
                  <div className="space-y-2">
                    <Label htmlFor="adminPasskey">Admin Passkey</Label>
                    <Input
                      id="adminPasskey"
                      type="password"
                      placeholder="Enter admin passkey"
                      value={formData.adminPasskey}
                      onChange={(e) => handleChange('adminPasskey', e.target.value)}
                    />
                  </div>
                )}

                {!isLogin && formData.role === 'student' && (
                  <div className="space-y-2">
                    <Label htmlFor="fingerprintId">Fingerprint</Label>
                    <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                      <Button type="button" onClick={handleScanFingerprint} disabled={isScanning} className="hover-glow">
                        {isScanning ? 'Scanning...' : 'Scan fingerprint'}
                      </Button>
                      <Input
                        id="fingerprintId"
                        type="text"
                        placeholder="No fingerprint captured"
                        value={formData.fingerprintId}
                        readOnly
                      />
                    </div>
                    <p className="text-xs text-muted-foreground">This triggers a future scanner/SDK. We only store a reference ID.</p>
                  </div>
                )}
                
                <Button
                  type="submit"
                  className="w-full hover-glow"
                  disabled={loading}
                >
                  {loading ? 'Please wait...' : (isLogin ? 'Sign In' : 'Create Account')}
                </Button>
              </form>
              
              <div className="mt-4 text-center">
                <button
                  type="button"
                  onClick={() => setIsLogin(!isLogin)}
                  className="text-sm text-primary hover:underline"
                >
                  {isLogin ? "Don't have an account? Sign up" : 'Already have an account? Sign in'}
                </button>
              </div>
              
              {/* Demo Credentials */}
              <div className="mt-4 p-3 bg-muted/50 rounded-lg text-xs">
                <p className="font-medium mb-1">Demo Credentials:</p>
                <p>Admin: admin@demo.com / password</p>
                <p>Student: student@demo.com / password</p>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}