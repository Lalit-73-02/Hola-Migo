import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, User, Mail, Lock, UserCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthSuccess: (user: any) => void;
}

interface FormData {
  name: string;
  email: string;
  password: string;
  role: "admin" | "student" | "";
  adminPasskey?: string;
  fingerprintId?: string;
}

export default function AuthModal({ isOpen, onClose, onAuthSuccess }: AuthModalProps) {
  const [isSignUp, setIsSignUp] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [formData, setFormData] = useState<FormData>({
    name: "",
    email: "",
    password: "",
    role: "",
    adminPasskey: "",
    fingerprintId: ""
  });
  const { toast } = useToast();
  const { login, register } = useAuth();

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (isSignUp) {
      if (!formData.name || !formData.email || !formData.password || !formData.role) {
        toast({
          title: "Error",
          description: "Please fill in all fields",
          variant: "destructive",
        });
        return;
      }

      if (formData.role === "admin") {
        const expected = import.meta.env.VITE_ADMIN_PASSKEY || "ADMIN-1234";
        if (!formData.adminPasskey || formData.adminPasskey !== expected) {
          toast({ title: "Invalid Passkey", description: "Admin passkey is incorrect.", variant: "destructive" });
          return;
        }
      }

      if (formData.role === "student" && !formData.fingerprintId) {
        toast({ title: "Fingerprint Required", description: "Please provide your fingerprint ID.", variant: "destructive" });
        return;
      }
      const result = await register(
        formData.email,
        formData.password,
        formData.name,
        formData.role as "admin" | "student",
        {
          fingerprintId: formData.role === "student" ? formData.fingerprintId : undefined
        }
      );

      if ("error" in result) {
        toast({ title: "Registration Failed", description: result.error, variant: "destructive" });
        return;
      }

      toast({ title: "Success!", description: "Account created successfully." });
      onAuthSuccess(result.user);
      onClose();
    } else {
      if (!formData.email || !formData.password) {
        toast({
          title: "Error",
          description: "Please enter email and password",
          variant: "destructive",
        });
        return;
      }
      const result = await login(formData.email, formData.password);
      if ("error" in result) {
        toast({ title: "Error", description: result.error, variant: "destructive" });
        return;
      }

      toast({ title: "Welcome!", description: `Successfully signed in as ${result.user.role}` });
      onAuthSuccess(result.user);
      onClose();
    }
  };

  const resetForm = () => {
    setFormData({ name: "", email: "", password: "", role: "", adminPasskey: "", fingerprintId: "" });
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
      if (!('PublicKeyCredential' in window)) {
        toast({ title: 'Biometrics not supported', description: 'Your browser/device does not support WebAuthn.', variant: 'destructive' });
        await new Promise((r) => setTimeout(r, 1200));
        const generatedId = `FP-${crypto.randomUUID().slice(0, 8)}`;
        setFormData((prev) => ({ ...prev, fingerprintId: generatedId }));
        return;
      }
      const uvpa = await (window as any).PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.();
      if (!uvpa) {
        toast({ title: 'Platform authenticator unavailable', description: 'Enable screen lock and enroll biometrics.', variant: 'destructive' });
        return;
      }
      try {
        const resp = await fetch(`${apiBase}/api/webauthn/register/options`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: formData.email, name: formData.name || 'Student' })
        });
        if (!resp.ok) throw new Error(`options ${resp.status}`);
        const { publicKey } = await resp.json();
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
      } catch (err: any) {
        toast({ title: 'Scan failed', description: String(err?.message || err), variant: 'destructive' });
      }
    } finally {
      setIsScanning(false);
    }
  };

  const toggleMode = () => {
    setIsSignUp(!isSignUp);
    resetForm();
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
          onClick={onClose}
        >
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.8, opacity: 0 }}
            transition={{ type: "spring", stiffness: 300, damping: 30 }}
            className="glass p-8 rounded-2xl w-full max-w-md"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center space-x-3">
                <div className="p-2 rounded-full bg-primary/10">
                  <UserCheck className="h-6 w-6 text-primary" />
                </div>
                <h2 className="text-2xl font-bold">
                  {isSignUp ? "Join Attendo" : "Welcome Back"}
                </h2>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={onClose}
                className="hover-glow"
              >
                <X className="h-5 w-5" />
              </Button>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-4">
              {isSignUp && (
                <div className="space-y-2">
                  <div className="relative">
                    <User className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                    <Input
                      type="text"
                      name="name"
                      placeholder="Full Name"
                      value={formData.name}
                      onChange={handleInputChange}
                      className="pl-10 glass border-primary/20 focus:border-primary/50"
                      required={isSignUp}
                    />
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                  <Input
                    type="email"
                    name="email"
                    placeholder="Email Address"
                    value={formData.email}
                    onChange={handleInputChange}
                    className="pl-10 glass border-primary/20 focus:border-primary/50"
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                  <Input
                    type="password"
                    name="password"
                    placeholder="Password"
                    value={formData.password}
                    onChange={handleInputChange}
                    className="pl-10 glass border-primary/20 focus:border-primary/50"
                    required
                  />
                </div>
              </div>

              {isSignUp && (
                <div className="space-y-2">
                  <Select
                    value={formData.role}
                    onValueChange={(value) => 
                      setFormData({ ...formData, role: value as "admin" | "student" })
                    }
                  >
                    <SelectTrigger className="glass border-primary/20 focus:border-primary/50">
                      <SelectValue placeholder="Select your role" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="student">Student</SelectItem>
                      <SelectItem value="admin">Administrator</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}

              {isSignUp && formData.role === "admin" && (
                <div className="space-y-2">
                  <div className="relative">
                    <Input
                      type="password"
                      name="adminPasskey"
                      placeholder="Enter admin passkey"
                      value={formData.adminPasskey}
                      onChange={handleInputChange}
                      className="glass border-primary/20 focus:border-primary/50"
                    />
                  </div>
                </div>
              )}

              {isSignUp && formData.role === "student" && (
                <div className="space-y-2">
                  <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                    <Button type="button" onClick={handleScanFingerprint} disabled={isScanning} className="hover-glow">
                      {isScanning ? "Scanning..." : "Scan fingerprint"}
                    </Button>
                    <Input
                      type="text"
                      name="fingerprintId"
                      placeholder="No fingerprint captured"
                      value={formData.fingerprintId}
                      readOnly
                      className="glass border-primary/20 focus:border-primary/50"
                    />
                  </div>
                  <p className="text-xs text-muted-foreground">This triggers a future scanner/SDK. Stored as a reference ID only.</p>
                </div>
              )}

              <Button
                type="submit"
                className="w-full bg-primary hover:bg-primary/90 text-primary-foreground hover-glow"
                size="lg"
              >
                {isSignUp ? "Create Account" : "Sign In"}
              </Button>
            </form>

            {/* Toggle Mode */}
            <div className="mt-6 text-center">
              <p className="text-muted-foreground">
                {isSignUp ? "Already have an account?" : "Don't have an account?"}
                <button
                  type="button"
                  onClick={toggleMode}
                  className="ml-2 text-primary hover:underline font-medium"
                >
                  {isSignUp ? "Sign In" : "Sign Up"}
                </button>
              </p>
            </div>

            {/* Demo Credentials */}
            {!isSignUp && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="mt-6 p-4 bg-muted/30 rounded-lg text-sm"
              >
                <p className="font-medium mb-2">Demo Credentials:</p>
                <p><strong>Admin:</strong> admin@demo.com / password</p>
                <p><strong>Student:</strong> student@demo.com / password</p>
              </motion.div>
            )}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}