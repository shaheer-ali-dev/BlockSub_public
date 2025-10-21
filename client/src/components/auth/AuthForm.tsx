import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Loader2, Eye, EyeOff, Lock, User, AlertCircle, CheckCircle2 } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface AuthFormProps {
  mode: 'login' | 'signup';
  onSubmit: (credentials: { username: string; password: string; email?: string; otpCode?: string }) => Promise<void>;
  onModeChange: (mode: 'login' | 'signup') => void;
  loading: boolean;
}

interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
}

const validateUsername = (username: string): ValidationResult => {
  const errors: string[] = [];
  const warnings: string[] = [];
  
  if (!username) {
    errors.push('Username is required');
  } else {
    if (username.length < 3) {
      errors.push('Username must be at least 3 characters');
    }
    if (username.length > 30) {
      errors.push('Username must be less than 30 characters');
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      errors.push('Username can only contain letters, numbers, underscore, and hyphen');
    }
  }
  
  return { isValid: errors.length === 0, errors, warnings };
};

const validatePassword = (password: string, isSignup: boolean = false): ValidationResult => {
  const errors: string[] = [];
  const warnings: string[] = [];
  
  if (!password) {
    errors.push('Password is required');
    return { isValid: false, errors, warnings };
  }
  
  if (!isSignup) {
    return { isValid: true, errors, warnings };
  }
  
  // Signup password validation
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[@$!%*?&]/.test(password)) {
    errors.push('Password must contain at least one special character (@$!%*?&)');
  }
  
  // Warnings for weak passwords
  if (password.length < 12) {
    warnings.push('Consider using a longer password for better security');
  }
  
  if (/^[a-zA-Z]+$/.test(password)) {
    warnings.push('Consider adding numbers and special characters');
  }
  
  return { isValid: errors.length === 0, errors, warnings };
};

export function AuthForm({ mode, onSubmit, onModeChange, loading }: AuthFormProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [sendingOtp, setSendingOtp] = useState(false);
  const [verifyingOtp, setVerifyingOtp] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [touched, setTouched] = useState({ username: false, password: false });
  const { toast } = useToast();
  
  const isSignup = mode === 'signup';
  const usernameValidation = validateUsername(username);
  const passwordValidation = validatePassword(password, isSignup);
  
  const showUsernameError = touched.username && !usernameValidation.isValid;
  const showPasswordError = touched.password && !passwordValidation.isValid;
  
  const isFormValid = usernameValidation.isValid && passwordValidation.isValid;
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Mark all fields as touched
    setTouched({ username: true, password: true });
    
    if (!isFormValid) {
      toast({
        title: 'Validation Error',
        description: 'Please fix the errors below before continuing.',
        variant: 'destructive',
      });
      return;
    }
    
    try {
      // When signing up include email and otpCode so server can validate OTP
      await onSubmit({ username, password, email: isSignup ? email : undefined, otpCode: isSignup ? otpCode : undefined });
    } catch (error) {
      // Error handling is done in the parent component
    }
  };

  const sendOtp = async () => {
    if (!email) {
      toast({ title: 'Email required', description: 'Please enter your email to receive an OTP', variant: 'destructive' });
      return;
    }

    try {
      setSendingOtp(true);
      const res = await fetch('/api/auth/send-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.message || 'Failed to send OTP');
      }

      setOtpSent(true);
      toast({ title: 'OTP Sent', description: `A verification code was sent to ${email}` });
    } catch (err: any) {
      toast({ title: 'Failed to send OTP', description: err?.message || String(err), variant: 'destructive' });
    } finally {
      setSendingOtp(false);
    }
  };

  const verifyOtp = async () => {
    if (!email || !otpCode) {
      toast({ title: 'Missing fields', description: 'Email and code are required to verify', variant: 'destructive' });
      return;
    }

    try {
      setVerifyingOtp(true);
      const res = await fetch('/api/auth/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code: otpCode }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.message || 'Verification failed');
      }

      toast({ title: 'Verified', description: 'OTP verified — you can now complete signup' });
    } catch (err: any) {
      toast({ title: 'Verification failed', description: err?.message || String(err), variant: 'destructive' });
    } finally {
      setVerifyingOtp(false);
    }
  };
  
  const getPasswordStrength = (password: string): { strength: number; label: string; color: string } => {
    let strength = 0;
    
    if (password.length >= 8) strength += 20;
    if (password.length >= 12) strength += 10;
    if (/[a-z]/.test(password)) strength += 20;
    if (/[A-Z]/.test(password)) strength += 20;
    if (/\d/.test(password)) strength += 15;
    if (/[@$!%*?&]/.test(password)) strength += 15;
    
    if (strength < 40) return { strength, label: 'Weak', color: 'bg-red-500' };
    if (strength < 70) return { strength, label: 'Medium', color: 'bg-yellow-500' };
    return { strength, label: 'Strong', color: 'bg-green-500' };
  };
  
  const passwordStrength = getPasswordStrength(password);
  
  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader className="space-y-1">
        <CardTitle className="text-2xl font-bold text-center">
          {isSignup ? 'Create Account' : 'Welcome Back'}
        </CardTitle>
        <CardDescription className="text-center text-muted-foreground">
          {isSignup 
            ? 'Sign up to start managing your API keys'
            : 'Sign in to your account to continue'
          }
        </CardDescription>
      </CardHeader>
      
      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-4">
          {/* Email Field (Signup only) */}
          {isSignup && (
            <div className="space-y-2">
              <Label htmlFor="email" className="flex items-center gap-2">
                <User className="w-4 h-4" />
                Email
              </Label>
              <div className="flex gap-2">
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  disabled={loading}
                  autoComplete="email"
                />
                <Button type="button" onClick={sendOtp} disabled={sendingOtp || loading}>
                  {sendingOtp ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Send OTP'}
                </Button>
              </div>
              {otpSent && (
                <Alert className="py-2">
                  <CheckCircle2 className="h-4 w-4 text-green-600" />
                  <AlertDescription className="ml-2">A verification code was sent to {email}</AlertDescription>
                </Alert>
              )}
            </div>
          )}
          {/* Username Field */}
          <div className="space-y-2">
            <Label htmlFor="username" className="flex items-center gap-2">
              <User className="w-4 h-4" />
              Username
            </Label>
            <Input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              onBlur={() => setTouched(prev => ({ ...prev, username: true }))}
              placeholder="Enter your username"
              className={showUsernameError ? 'border-red-500 focus:ring-red-500' : ''}
              disabled={loading}
              autoComplete="username"
            />
            
            {showUsernameError && (
              <Alert variant="destructive" className="py-2">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  <ul className="list-disc list-inside space-y-1">
                    {usernameValidation.errors.map((error, index) => (
                      <li key={index} className="text-sm">{error}</li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            )}
          </div>
          
          {/* Password Field */}
          <div className="space-y-2">
            <Label htmlFor="password" className="flex items-center gap-2">
              <Lock className="w-4 h-4" />
              Password
            </Label>
            <div className="relative">
              <Input
                id="password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onBlur={() => setTouched(prev => ({ ...prev, password: true }))}
                placeholder="Enter your password"
                className={`pr-10 ${showPasswordError ? 'border-red-500 focus:ring-red-500' : ''}`}
                disabled={loading}
                autoComplete={isSignup ? 'new-password' : 'current-password'}
              />
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                onClick={() => setShowPassword(!showPassword)}
                disabled={loading}
              >
                {showPassword ? (
                  <EyeOff className="h-4 w-4 text-muted-foreground" />
                ) : (
                  <Eye className="h-4 w-4 text-muted-foreground" />
                )}
              </Button>
            </div>
            
            {/* Password Strength Indicator for Signup */}
            {isSignup && password && (
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>Password Strength</span>
                  <span className={`font-medium ${
                    passwordStrength.strength < 40 ? 'text-red-600' : 
                    passwordStrength.strength < 70 ? 'text-yellow-600' : 'text-green-600'
                  }`}>
                    {passwordStrength.label}
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div 
                    className={`h-2 rounded-full transition-all ${passwordStrength.color}`}
                    style={{ width: `${passwordStrength.strength}%` }}
                  />
                </div>
              </div>
            )}
            
            {showPasswordError && (
              <Alert variant="destructive" className="py-2">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  <ul className="list-disc list-inside space-y-1">
                    {passwordValidation.errors.map((error, index) => (
                      <li key={index} className="text-sm">{error}</li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            )}
            
            {/* Password Warnings for Signup */}
            {isSignup && passwordValidation.isValid && passwordValidation.warnings.length > 0 && (
              <Alert className="py-2 border-yellow-200 bg-yellow-50">
                <AlertCircle className="h-4 w-4 text-yellow-600" />
                <AlertDescription>
                  <ul className="list-disc list-inside space-y-1 text-yellow-800">
                    {passwordValidation.warnings.map((warning, index) => (
                      <li key={index} className="text-sm">{warning}</li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            )}

            {/* OTP Code Field (Signup) */}
            {isSignup && (
              <div className="space-y-2">
                <Label htmlFor="otp" className="flex items-center gap-2">
                  <User className="w-4 h-4" />
                  Verification Code
                </Label>
                <div className="flex gap-2">
                  <Input
                    id="otp"
                    type="text"
                    value={otpCode}
                    onChange={(e) => setOtpCode(e.target.value)}
                    placeholder="Enter verification code"
                    disabled={loading}
                  />
                  <Button type="button" onClick={verifyOtp} disabled={verifyingOtp || loading || !otpSent}>
                    {verifyingOtp ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Verify'}
                  </Button>
                </div>
                {!otpSent && (
                  <p className="text-xs text-muted-foreground">Click "Send OTP" to receive a verification code via email.</p>
                )}
              </div>
            )}
          </div>
        </CardContent>
        
        <CardFooter className="flex flex-col space-y-4">
          <Button 
            type="submit" 
            className="w-full" 
            disabled={loading || !isFormValid}
          >
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                {isSignup ? 'Creating Account...' : 'Signing In...'}
              </>
            ) : (
              <>
                {isSignup ? (
                  <>
                    <CheckCircle2 className="mr-2 h-4 w-4" />
                    Create Account
                  </>
                ) : (
                  <>
                    <Lock className="mr-2 h-4 w-4" />
                    Sign In
                  </>
                )}
              </>
            )}
          </Button>
          
          <div className="text-center text-sm text-muted-foreground">
            {isSignup ? (
              <>
                Already have an account?{' '}
                <Button 
                  type="button" 
                  variant="link" 
                  className="p-0 h-auto font-semibold text-primary"
                  onClick={() => onModeChange('login')}
                  disabled={loading}
                >
                  Sign in
                </Button>
              </>
            ) : (
              <>
                Don't have an account?{' '}
                <Button 
                  type="button" 
                  variant="link" 
                  className="p-0 h-auto font-semibold text-primary"
                  onClick={() => onModeChange('signup')}
                  disabled={loading}
                >
                  Sign up
                </Button>
              </>
            )}
          </div>
        </CardFooter>
      </form>
    </Card>
  );
}
