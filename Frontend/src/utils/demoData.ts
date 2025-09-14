// Initialize demo data for Attendo aligned with useAuth storage keys

export const initializeDemoData = () => {
  // If legacy key exists and new key is empty, migrate
  const legacyUsersRaw = localStorage.getItem('attendo-users');
  const newUsersRaw = localStorage.getItem('attendo_users');

  if (legacyUsersRaw && !newUsersRaw) {
    try {
      const legacyUsers = JSON.parse(legacyUsersRaw) as Array<{ id: string; email: string; name: string; role: 'admin' | 'student'; password?: string }>;
      const usersForNewKey = legacyUsers.map(u => ({
        id: u.id,
        email: u.email,
        name: u.name,
        role: u.role,
        createdAt: new Date().toISOString(),
      }));
      localStorage.setItem('attendo_users', JSON.stringify(usersForNewKey));
      // store passwords per-id if present
      legacyUsers.forEach(u => {
        if (u.password) {
          localStorage.setItem(`attendo_password_${u.id}`, u.password);
        }
      });
    } catch {
      // ignore migration errors
    }
  }

  // Seed demo users if still empty
  const existingUsersNew = localStorage.getItem('attendo_users');
  if (!existingUsersNew) {
    const demoUsers = [
      {
        id: 'demo-admin-1',
        name: 'Admin User',
        email: 'admin@demo.com',
        role: 'admin' as const,
      },
      {
        id: 'demo-student-1',
        name: 'Student User',
        email: 'student@demo.com',
        role: 'student' as const,
      },
      {
        id: 'demo-student-2',
        name: 'Alice Johnson',
        email: 'alice@demo.com',
        role: 'student' as const,
      },
      {
        id: 'demo-student-3',
        name: 'Bob Smith',
        email: 'bob@demo.com',
        role: 'student' as const,
      },
    ].map(u => ({ ...u, createdAt: new Date().toISOString() }));

    localStorage.setItem('attendo_users', JSON.stringify(demoUsers));
    // Set default password for demos
    demoUsers.forEach(u => {
      localStorage.setItem(`attendo_password_${u.id}`, 'password');
    });
  }
};

export const clearDemoData = () => {
  localStorage.removeItem('attendo-users');
  localStorage.removeItem('attendo-current-user');
  localStorage.removeItem('attendo_users');
  // Remove demo passwords
  const keysToRemove: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && key.startsWith('attendo_password_')) {
      keysToRemove.push(key);
    }
  }
  keysToRemove.forEach(k => localStorage.removeItem(k));
};