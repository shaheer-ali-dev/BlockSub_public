import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useToast } from '@/hooks/use-toast';

export interface User {
  id: string;
  username: string;
  createdAt: string;
  updatedAt?: string;
}

export interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (credentials: { username: string; password: string }) => Promise<void>;
// change line 219 to
const signup:(credentials: { username: string; password: string; email?: string; otpCode?: string): Promise<void> 
  logout: () => Promise<void>;
  refreshToken: () => Promise<boolean>;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

const API_BASE_URL = '/api/auth';

interface ApiResponse<T = any> {
  message?: string;
  user?: User;
  accessToken?: string;
  error?: string;
  details?: string[];
}

// Token management utilities
class TokenManager {
  private static readonly ACCESS_TOKEN_KEY = 'access_token';
  
  static setAccessToken(token: string): void {
    localStorage.setItem(this.ACCESS_TOKEN_KEY, token);
  }
  
  static getAccessToken(): string | null {
    return localStorage.getItem(this.ACCESS_TOKEN_KEY);
  }
  
  static removeAccessToken(): void {
    localStorage.removeItem(this.ACCESS_TOKEN_KEY);
  }
  
  static hasValidToken(): boolean {
    const token = this.getAccessToken();
    if (!token) return false;
    
    try {
      // Basic JWT structure validation
      const parts = token.split('.');
      if (parts.length !== 3) return false;
      
      // Decode payload
      const payload = JSON.parse(atob(parts[1]));
      
      // Check if token is expired (with 5 minute buffer)
      const now = Math.floor(Date.now() / 1000);
      const expiryBuffer = 5 * 60; // 5 minutes
      
      return payload.exp && payload.exp > (now + expiryBuffer);
    } catch {
      return false;
    }
  }
}

// HTTP client with authentication
class ApiClient {
  private static async request<T = any>(
    endpoint: string, 
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${API_BASE_URL}${endpoint}`;
    const token = TokenManager.getAccessToken();
    
    // Normalize headers to a plain object of string -> string
    const baseHeaders: Record<string, string> = { 'Content-Type': 'application/json' };

    if (options.headers) {
      const h = options.headers as HeadersInit;
      if (typeof (globalThis as any).Headers !== 'undefined' && h instanceof (globalThis as any).Headers) {
        (h as Headers).forEach((value, key) => {
          baseHeaders[key] = String(value);
        });
      } else if (Array.isArray(h)) {
        for (const [key, value] of h) {
          baseHeaders[key] = String(value);
        }
      } else {
        Object.assign(baseHeaders, h as Record<string, string>);
      }
    }

    if (token) {
      baseHeaders['Authorization'] = `Bearer ${token}`;
    }
    
    const config: RequestInit = {
      ...options,
      headers: baseHeaders,
      credentials: 'include', // Include cookies for refresh token
    };
    
    const response = await fetch(url, config);
    
    if (!response.ok) {
      const errorData: ApiResponse = await response.json().catch(() => ({
        error: 'Network error',
        message: 'An error occurred while communicating with the server'
      }));
      
      throw new Error(errorData.message || errorData.error || `HTTP ${response.status}`);
    }
    
    return response.json();
  }
  
  static async post<T = any>(endpoint: string, data?: any): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    });
  }
  
  static async get<T = any>(endpoint: string): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'GET',
    });
  }
}

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();
  
  const isAuthenticated = !!user;
  
  // Initialize authentication state
  useEffect(() => {
    const initializeAuth = async () => {
      try {
        // Check if we have a valid access token
        if (TokenManager.hasValidToken()) {
          // Try to get user profile
          await fetchUserProfile();
        } else {
          // Try to refresh token
          const refreshed = await refreshToken();
          if (refreshed) {
            await fetchUserProfile();
          }
        }
      } catch (error) {
        console.error('Auth initialization failed:', error);
        // Clear any invalid tokens
        TokenManager.removeAccessToken();
      } finally {
        setLoading(false);
      }
    };
    
    initializeAuth();
  }, []);
  
  const fetchUserProfile = async (): Promise<void> => {
    try {
      const response: ApiResponse = await ApiClient.get('/profile');
      if (response.user) {
        setUser(response.user);
      }
    } catch (error) {
      console.error('Failed to fetch user profile:', error);
      throw error;
    }
  };
  
  const login = async (credentials: { username: string; password: string }): Promise<void> => {
    try {
      setLoading(true);
      
      const response: ApiResponse = await ApiClient.post('/login', credentials);
      
      if (response.accessToken && response.user) {
        TokenManager.setAccessToken(response.accessToken);
        setUser(response.user);
        
        toast({
          title: 'Login Successful',
          description: `Welcome back, ${response.user.username}!`,
        });
      } else {
        throw new Error('Invalid response from server');
      }
    } catch (error: any) {
      console.error('Login failed:', error);
      
      toast({
        title: 'Login Failed',
        description: error.message || 'An error occurred during login',
        variant: 'destructive',
      });
      
      throw error;
    } finally {
      setLoading(false);
    }
  };
  
// change line 219 to
const signup = async (credentials: { username: string; password: string; email?: string; otpCode?: string}): Promise<void> => {
    try {
      setLoading(true);
      
      // POST signup with optional email and otpCode for server-side verification
      const response: ApiResponse = await ApiClient.post('/signup', credentials);
      
      if (response.accessToken && response.user) {
        TokenManager.setAccessToken(response.accessToken);
        setUser(response.user);
        
        toast({
          title: 'Account Created',
          description: `Welcome to BlockSub, ${response.user.username}!`,
        });
      } else {
        throw new Error('Invalid response from server');
      }
    } catch (error: any) {
      console.error('Signup failed:', error);
      
      toast({
        title: 'Signup Failed',
        description: error.message || 'An error occurred during signup',
        variant: 'destructive',
      });
      
      throw error;
    } finally {
      setLoading(false);
    }
  };
  
  const logout = async (): Promise<void> => {
    try {
      // Call logout endpoint to clear server-side session
      await ApiClient.post('/logout');
    } catch (error) {
      console.error('Logout API call failed:', error);
      // Continue with logout even if API call fails
    } finally {
      // Clear client-side state
      TokenManager.removeAccessToken();
      setUser(null);
      
      toast({
        title: 'Logged Out',
        description: 'You have been successfully logged out.',
      });
    }
  };
  
  const refreshToken = async (): Promise<boolean> => {
    try {
      const response: ApiResponse = await ApiClient.post('/refresh');
      
      if (response.accessToken) {
        TokenManager.setAccessToken(response.accessToken);
        return true;
      }
      
      return false;
    } catch (error) {
      console.error('Token refresh failed:', error);
      // Clear invalid tokens
      TokenManager.removeAccessToken();
      return false;
    }
  };
  
  // Auto-refresh token before expiry
  useEffect(() => {
    if (!isAuthenticated) return;
    
    const refreshInterval = setInterval(async () => {
      try {
        const token = TokenManager.getAccessToken();
        if (!token) return;
        
        // Check if token expires in next 5 minutes
        const parts = token.split('.');
        if (parts.length !== 3) return;
        
        const payload = JSON.parse(atob(parts[1]));
        const now = Math.floor(Date.now() / 1000);
        const expiresInMinutes = (payload.exp - now) / 60;
        
        if (expiresInMinutes <= 5) {
          const refreshed = await refreshToken();
          if (!refreshed) {
            // Refresh failed, logout user
            await logout();
          }
        }
      } catch (error) {
        console.error('Auto-refresh failed:', error);
      }
    }, 60000); // Check every minute
    
    return () => clearInterval(refreshInterval);
  }, [isAuthenticated]);
  
  const value: AuthContextType = {
    user,
    loading,
    login,
    signup,
    logout,
    refreshToken,
    isAuthenticated,
  };
  
  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

// Higher-order component for protected routes
export function withAuth<P extends object>(Component: React.ComponentType<P>) {
  return function AuthenticatedComponent(props: P) {
    const { isAuthenticated, loading } = useAuth();
    
    if (loading) {
      return (
        <div className="flex items-center justify-center min-h-screen">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      );
    }
    
    if (!isAuthenticated) {
      // Redirect to login or show login form
      return <div>Please log in to access this page</div>;
    }
    
    return <Component {...props} />;
  };
}

// Hook for API calls with automatic token handling
export function useApiClient() {
  return {
    get: ApiClient.get,
    post: ApiClient.post,
  };

}


