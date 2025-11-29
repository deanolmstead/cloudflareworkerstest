import { Router, json } from 'itty-router';

const router = Router();

// Define types
interface User {
  id: string;
  email: string;
  name?: string;
}

interface AuthRequest {
  email: string;
  password: string;
}

// Mock user database (replace with real database in production)
const MOCK_USERS: Record<string, { password: string; name: string }> = {
  'test@example.com': { password: 'password123', name: 'Test User' },
  'demo@example.com': { password: 'demo123', name: 'Demo User' }
};

// Helper function to generate session token
function generateToken(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Helper function to set secure cookie
function setCookie(response: Response, name: string, value: string, maxAge: number = 86400): Response {
  const cookie = `${name}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
  response.headers.append('Set-Cookie', cookie);
  return response;
}

// Helper function to get cookie value
function getCookie(request: Request, name: string): string | null {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(';');
  for (const cookie of cookies) {
    const [cookieName, cookieValue] = cookie.trim().split('=');
    if (cookieName === name) {
      return cookieValue;
    }
  }
  return null;
}

// Mock session store (use KV or database in production)
const sessions = new Map<string, { user: User; expiresAt: number }>();

// Login endpoint
router.post('/api/login', async (request: Request) => {
  try {
    const body: AuthRequest = await request.json();
    const { email, password } = body;

    // Validate input
    if (!email || !password) {
      return json({ error: 'Email and password are required' }, { status: 400 });
    }

    // Check credentials against mock database
    const user = MOCK_USERS[email];
    if (!user || user.password !== password) {
      return json({ error: 'Invalid email or password' }, { status: 401 });
    }

    // Create session
    const sessionToken = generateToken();
    const userData: User = {
      id: `user_${Date.now()}`,
      email,
      name: user.name
    };

    sessions.set(sessionToken, {
      user: userData,
      expiresAt: Date.now() + 86400000 // 24 hours
    });

    // Create response with session cookie
    const response = json(userData, { status: 200 });
    return setCookie(response, 'auth_token', sessionToken);
  } catch (error) {
    console.error('Login error:', error);
    return json({ error: 'Internal server error' }, { status: 500 });
  }
});

// Verify endpoint (check if authenticated)
router.get('/api/verify', (request: Request) => {
  try {
    const sessionToken = getCookie(request, 'auth_token');

    if (!sessionToken) {
      return json({ error: 'Not authenticated' }, { status: 401 });
    }

    const session = sessions.get(sessionToken);

    if (!session) {
      return json({ error: 'Session not found' }, { status: 401 });
    }

    if (session.expiresAt < Date.now()) {
      sessions.delete(sessionToken);
      return json({ error: 'Session expired' }, { status: 401 });
    }

    return json(session.user, { status: 200 });
  } catch (error) {
    console.error('Verify error:', error);
    return json({ error: 'Internal server error' }, { status: 500 });
  }
});

// Logout endpoint
router.post('/api/logout', (request: Request) => {
  const sessionToken = getCookie(request, 'auth_token');

  if (sessionToken) {
    sessions.delete(sessionToken);
  }

  const response = json({ message: 'Logged out successfully' });
  // Clear the cookie by setting Max-Age to 0
  response.headers.append('Set-Cookie', 'auth_token=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict');

  return response;
});

// Serve static files (index.html, styles.css, script.js)
router.get('/', () => {
  return fetch('https://your-domain.com/index.html');
});

router.get('/styles.css', () => {
  return fetch('https://your-domain.com/styles.css');
});

router.get('/script.js', () => {
  return fetch('https://your-domain.com/script.js');
});

// 404 handler
router.all('*', () => {
  return json({ error: 'Not found' }, { status: 404 });
});

export default router;
