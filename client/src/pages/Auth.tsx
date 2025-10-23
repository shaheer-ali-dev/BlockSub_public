import React, { useState } from 'react';
import { useLocation } from 'wouter';
import { AuthForm } from '@/components/auth/AuthForm';
import { useAuth } from '@/contexts/AuthContext';
import { Navigation } from '@/components/Navigation';

export default function Auth() {
  const [mode, setMode] = useState<'login' | 'signup'>('login');
  const [, setLocation] = useLocation();
  const { login, signup, loading, isAuthenticated } = useAuth();

  // Redirect if already authenticated
  React.useEffect(() => {
    if (isAuthenticated) {
      setLocation('/dashboard');
    }
  }, [isAuthenticated, setLocation]);

  const handleSubmit = async (credentials: { username: string; password: string; email?: string; otpCode?: string }) => {
    try {
      if (mode === 'login') {
        await login(credentials);
      } else {
        await signup(credentials);
      }
      
      // Redirect to dashboard after successful authentication
      setLocation('/dashboard');
    } catch (error) {
      // Error handling is done in the auth context
      console.error('Authentication error:', error);
    }
  };

  const handleModeChange = (newMode: 'login' | 'signup') => {
    setMode(newMode);
  };

  if (isAuthenticated) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-background to-muted/30">
      <Navigation />
      
      <div className="container mx-auto px-4 py-24">
        <div className="flex flex-col items-center justify-center min-h-[calc(100vh-12rem)]">
          {/* Header */}
          <div className="text-center mb-8">
            <h1 className="text-4xl font-bold text-foreground mb-2">
              {mode === 'login' ? 'Welcome Back' : 'Get Started'}
            </h1>
            <p className="text-xl text-muted-foreground max-w-md">
              {mode === 'login' 
                ? 'Sign in to manage your API keys and continue your blockchain subscription journey.'
                : 'Create your account and start building with our powerful API platform.'
              }
            </p>
          </div>

          {/* Authentication Form */}
          <div className="w-full max-w-md">
            <AuthForm
              mode={mode}
              onSubmit={handleSubmit}
              onModeChange={handleModeChange}
              loading={loading}
            />
          </div>

          {/* Security Notice */}
          <div className="mt-8 max-w-md text-center">
            <p className="text-xs text-muted-foreground">
              By {mode === 'login' ? 'signing in' : 'creating an account'}, you agree to our{' '}
              <a href="#" className="text-primary hover:underline">
                Terms of Service
              </a>{' '}
              and{' '}
              <a href="#" className="text-primary hover:underline">
                Privacy Policy
              </a>
              . Your data is encrypted and secure.
            </p>
          </div>

          {/* Features Preview for Signup */}
          {mode === 'signup' && (
            <div className="mt-12 max-w-4xl">
              <div className="text-center mb-8">
                <h2 className="text-2xl font-semibold text-foreground mb-2">
                  Why Choose BlockSub?
                </h2>
                <p className="text-muted-foreground">
                  Everything you need to integrate blockchain subscriptions
                </p>
              </div>
              
              <div className="grid md:grid-cols-3 gap-6">
                <div className="text-center p-6 bg-card rounded-lg border">
                  <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mx-auto mb-4">
                    <svg className="w-6 h-6 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                  </div>
                  <h3 className="font-semibold mb-2">Secure API Keys</h3>
                  <p className="text-sm text-muted-foreground">
                    Enterprise-grade encryption and secure key management
                  </p>
                </div>
                
                <div className="text-center p-6 bg-card rounded-lg border">
                  <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mx-auto mb-4">
                    <svg className="w-6 h-6 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                    </svg>
                  </div>
                  <h3 className="font-semibold mb-2">Lightning Fast</h3>
                  <p className="text-sm text-muted-foreground">
                    Sub-second response times with global CDN
                  </p>
                </div>
                
                <div className="text-center p-6 bg-card rounded-lg border">
                  <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mx-auto mb-4">
                    <svg className="w-6 h-6 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <h3 className="font-semibold mb-2">99.9% Uptime</h3>
                  <p className="text-sm text-muted-foreground">
                    Reliable infrastructure you can count on
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
