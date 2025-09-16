import { createContext, useContext, useEffect, useState, ReactNode } from 'react';

export interface User {
  id: string;
  email: string;
  role: 'admin' | 'student';
  name: string;
  createdAt: string;
}

interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => Promise<{ user: User } | { error: string }>;
  register: (
    email: string,
    password: string,
    name: string,
    role: 'admin' | 'student'
  ) => Promise<{ user: User } | { error: string }>;
  logout: () => void;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check for stored user session
    const storedUser = localStorage.getItem('attendo_user');
    if (storedUser) {
      setUser(JSON.parse(storedUser));
    }
    setLoading(false);
  }, []);

  const login = async (email: string, password: string) => {
    try {
      // Get all users from localStorage
      const usersData = localStorage.getItem('attendo_users');
      const users: User[] = usersData ? JSON.parse(usersData) : [];
      
      // Find user with matching email and password
      const foundUser = users.find(u => u.email === email);
      
      if (!foundUser) {
        return { error: 'User not found' };
      }
      
      // In a real app, you'd hash passwords. For demo, we store plain text
      const storedPassword = localStorage.getItem(`attendo_password_${foundUser.id}`);
      if (storedPassword !== password) {
        return { error: 'Invalid password' };
      }
      
      setUser(foundUser);
      localStorage.setItem('attendo_user', JSON.stringify(foundUser));
      
      return { user: foundUser };
    } catch (error) {
      return { error: 'Login failed' };
    }
  };

  const register = async (
    email: string,
    password: string,
    name: string,
    role: 'admin' | 'student'
  ) => {
    try {
      // Check if user already exists
      const usersData = localStorage.getItem('attendo_users');
      const users: User[] = usersData ? JSON.parse(usersData) : [];
      
      if (users.find(u => u.email === email)) {
        return { error: 'User already exists' };
      }
      
      // Create new user
      const newUser: User = {
        id: crypto.randomUUID(),
        email,
        name,
        role,
        createdAt: new Date().toISOString()
      };
      
      // Store user data
      users.push(newUser);
      localStorage.setItem('attendo_users', JSON.stringify(users));
      localStorage.setItem(`attendo_password_${newUser.id}`, password);
      
      setUser(newUser);
      localStorage.setItem('attendo_user', JSON.stringify(newUser));
      
      return { user: newUser };
    } catch (error) {
      return { error: 'Registration failed' };
    }
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('attendo_user');
  };

  return (
    <AuthContext.Provider value={{ user, login, register, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}