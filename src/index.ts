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

interface Todo {
  id: string;
  userId: string;
  title: string;
  description?: string;
  completed: boolean;
  createdAt: number;
  updatedAt: number;
}

interface CreateTodoRequest {
  title: string;
  description?: string;
}

interface UpdateTodoRequest {
  title?: string;
  description?: string;
  completed?: boolean;
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

// Helper function to generate consistent user ID from email
function getUserIdFromEmail(email: string): string {
  // Create a simple hash from email for consistent ID across sessions
  let hash = 0;
  for (let i = 0; i < email.length; i++) {
    const char = email.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return `user_${Math.abs(hash).toString(16)}`;
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

// Mock todo database (use KV or database in production)
const todos = new Map<string, Todo>();

// Helper function to get user from request
function getUserFromRequest(request: Request): User | null {
  const sessionToken = getCookie(request, 'auth_token');
  if (!sessionToken) return null;

  const session = sessions.get(sessionToken);
  if (!session || session.expiresAt < Date.now()) {
    return null;
  }

  return session.user;
}

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
      id: getUserIdFromEmail(email),
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

// TODO ENDPOINTS

// Get all todos for authenticated user
router.get('/api/todos', (request: Request) => {
  try {
    const user = getUserFromRequest(request);
    if (!user) {
      return json({ error: 'Not authenticated' }, { status: 401 });
    }

    const userTodos = Array.from(todos.values()).filter(todo => todo.userId === user.id);
    return json(userTodos, { status: 200 });
  } catch (error) {
    console.error('Get todos error:', error);
    return json({ error: 'Internal server error' }, { status: 500 });
  }
});

// Create a new todo
router.post('/api/todos', async (request: Request) => {
  try {
    const user = getUserFromRequest(request);
    if (!user) {
      return json({ error: 'Not authenticated' }, { status: 401 });
    }

    const body: CreateTodoRequest = await request.json();
    const { title, description } = body;

    if (!title || title.trim() === '') {
      return json({ error: 'Title is required' }, { status: 400 });
    }

    const todoId = `todo_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const now = Date.now();
    const todo: Todo = {
      id: todoId,
      userId: user.id,
      title: title.trim(),
      description: description?.trim(),
      completed: false,
      createdAt: now,
      updatedAt: now
    };

    todos.set(todoId, todo);
    return json(todo, { status: 201 });
  } catch (error) {
    console.error('Create todo error:', error);
    return json({ error: 'Internal server error' }, { status: 500 });
  }
});

// Update a todo
router.put('/api/todos/:id', async (request: Request, { id }: { id: string }) => {
  try {
    const user = getUserFromRequest(request);
    if (!user) {
      return json({ error: 'Not authenticated' }, { status: 401 });
    }

    const todo = todos.get(id);
    if (!todo) {
      return json({ error: 'Todo not found' }, { status: 404 });
    }

    if (todo.userId !== user.id) {
      return json({ error: 'Forbidden' }, { status: 403 });
    }

    const body: UpdateTodoRequest = await request.json();
    const { title, description, completed } = body;

    const updatedTodo: Todo = {
      ...todo,
      ...(title !== undefined && { title: title.trim() }),
      ...(description !== undefined && { description: description.trim() || undefined }),
      ...(completed !== undefined && { completed }),
      updatedAt: Date.now()
    };

    todos.set(id, updatedTodo);
    return json(updatedTodo, { status: 200 });
  } catch (error) {
    console.error('Update todo error:', error);
    return json({ error: 'Internal server error' }, { status: 500 });
  }
});

// Delete a todo
router.delete('/api/todos/:id', (request: Request, { id }: { id: string }) => {
  try {
    const user = getUserFromRequest(request);
    if (!user) {
      return json({ error: 'Not authenticated' }, { status: 401 });
    }

    const todo = todos.get(id);
    if (!todo) {
      return json({ error: 'Todo not found' }, { status: 404 });
    }

    if (todo.userId !== user.id) {
      return json({ error: 'Forbidden' }, { status: 403 });
    }

    todos.delete(id);
    return json({ message: 'Todo deleted successfully' }, { status: 200 });
  } catch (error) {
    console.error('Delete todo error:', error);
    return json({ error: 'Internal server error' }, { status: 500 });
  }
});

// Embedded static files
const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auth Test - Cloudflare Workers</title>
    <style>
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 20px;
}

.container {
    width: 100%;
    max-width: 500px;
}

.card {
    background: white;
    border-radius: 8px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
    padding: 40px;
}

h1 {
    color: #333;
    margin-bottom: 30px;
    text-align: center;
    font-size: 28px;
}

h2 {
    color: #667eea;
    font-size: 18px;
    margin-top: 20px;
    margin-bottom: 15px;
}

.form-group {
    margin-bottom: 20px;
    display: flex;
    flex-direction: column;
}

label {
    color: #555;
    margin-bottom: 8px;
    font-weight: 500;
}

input {
    padding: 12px;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 14px;
    transition: border-color 0.3s;
}

input:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

.btn {
    padding: 12px 24px;
    border: none;
    border-radius: 4px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s;
    width: 100%;
}

.btn-primary {
    background-color: #667eea;
    color: white;
}

.btn-primary:hover {
    background-color: #5568d3;
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
}

.btn-secondary {
    background-color: #f0f0f0;
    color: #333;
    margin-top: 10px;
}

.btn-secondary:hover {
    background-color: #e0e0e0;
}

.error-message {
    color: #e74c3c;
    font-size: 14px;
    margin-top: 10px;
    text-align: center;
}

.status-box {
    background-color: #d4edda;
    border: 1px solid #c3e6cb;
    border-radius: 4px;
    padding: 15px;
    margin-bottom: 30px;
    color: #155724;
}

.status-box p {
    margin-bottom: 10px;
    font-weight: 500;
}

.user-info {
    margin-top: 30px;
    padding-top: 30px;
    border-top: 1px solid #eee;
}

.user-data {
    background-color: #f5f5f5;
    padding: 15px;
    border-radius: 4px;
    font-size: 14px;
    color: #333;
    white-space: pre-wrap;
    word-break: break-all;
}

.hidden {
    display: none !important;
}

.todos-section {
    margin-top: 30px;
    padding-top: 30px;
    border-top: 1px solid #eee;
}

.todo-input-group {
    margin-bottom: 20px;
    display: flex;
    flex-direction: column;
    gap: 10px;
}

#todo-title {
    padding: 12px;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 14px;
}

#todo-description {
    padding: 12px;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 14px;
    resize: vertical;
    min-height: 80px;
    font-family: inherit;
}

.todos-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin-top: 20px;
}

.todo-item {
    background-color: #f9f9f9;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 15px;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 10px;
}

.todo-item.completed {
    background-color: #f0f0f0;
}

.todo-item.completed .todo-title {
    text-decoration: line-through;
    color: #999;
}

.todo-content {
    flex: 1;
    cursor: pointer;
}

.todo-title {
    font-weight: 500;
    color: #333;
    margin-bottom: 5px;
}

.todo-description {
    font-size: 13px;
    color: #666;
    margin-bottom: 8px;
    white-space: pre-wrap;
}

.todo-date {
    font-size: 12px;
    color: #999;
}

.todo-checkbox {
    margin-right: 10px;
    width: 20px;
    height: 20px;
    cursor: pointer;
}

.todo-actions {
    display: flex;
    gap: 5px;
}

.todo-actions button {
    padding: 6px 12px;
    font-size: 12px;
    border: none;
    border-radius: 3px;
    cursor: pointer;
    transition: all 0.2s;
}

.btn-edit {
    background-color: #667eea;
    color: white;
}

.btn-edit:hover {
    background-color: #5568d3;
}

.btn-delete {
    background-color: #e74c3c;
    color: white;
}

.btn-delete:hover {
    background-color: #c0392b;
}

.empty-state {
    text-align: center;
    color: #999;
    padding: 30px 0;
}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Authentication Test</h1>

            <div id="auth-status" class="status-box hidden">
                <p id="status-message"></p>
                <button id="logout-btn" class="btn btn-secondary">Logout</button>
            </div>

            <form id="login-form" class="form">
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" required>
                </div>

                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>

                <button type="submit" class="btn btn-primary">Login</button>
                <p class="error-message" id="error-message"></p>
            </form>

            <div id="user-info" class="user-info hidden">
                <h2>User Information</h2>
                <div id="user-data"></div>
            </div>

            <div id="todos-section" class="todos-section hidden">
                <h2>My Todos</h2>
                <div class="todo-input-group">
                    <input type="text" id="todo-title" placeholder="Add a new todo..." maxlength="100">
                    <textarea id="todo-description" placeholder="Description (optional)" maxlength="500"></textarea>
                    <button id="add-todo-btn" class="btn btn-primary">Add Todo</button>
                </div>
                <div id="todos-list" class="todos-list"></div>
            </div>
        </div>
    </div>

    <script>
// Configuration
const API_URL = '/api';

// DOM Elements
const loginForm = document.getElementById('login-form');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const errorMessage = document.getElementById('error-message');
const authStatus = document.getElementById('auth-status');
const statusMessage = document.getElementById('status-message');
const userInfo = document.getElementById('user-info');
const userDataDiv = document.getElementById('user-data');
const logoutBtn = document.getElementById('logout-btn');

// Check if user is already authenticated
async function checkAuth() {
    try {
        const response = await fetch(\`\${API_URL}/verify\`, {
            method: 'GET',
            credentials: 'include'
        });

        if (response.ok) {
            const data = await response.json();
            showAuthenticatedState(data);
        } else {
            showLoginForm();
        }
    } catch (error) {
        console.error('Error checking auth:', error);
        showLoginForm();
    }
}

// Handle login form submission
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorMessage.textContent = '';

    const email = emailInput.value.trim();
    const password = passwordInput.value;

    try {
        const response = await fetch(\`\${API_URL}/login\`, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (response.ok) {
            showAuthenticatedState(data);
        } else {
            errorMessage.textContent = data.error || 'Authentication failed';
        }
    } catch (error) {
        errorMessage.textContent = 'Error connecting to server';
        console.error('Login error:', error);
    }
});

// Handle logout
logoutBtn.addEventListener('click', async () => {
    try {
        await fetch(\`\${API_URL}/logout\`, {
            method: 'POST',
            credentials: 'include'
        });
        showLoginForm();
    } catch (error) {
        console.error('Logout error:', error);
    }
});

// Show authenticated state
function showAuthenticatedState(user) {
    loginForm.classList.add('hidden');
    authStatus.classList.remove('hidden');
    userInfo.classList.remove('hidden');
    document.getElementById('todos-section').classList.remove('hidden');

    statusMessage.textContent = \`✓ Successfully authenticated as \${user.email}\`;
    userDataDiv.textContent = JSON.stringify(user, null, 2);

    loadTodos();
}

// Show login form
function showLoginForm() {
    loginForm.classList.remove('hidden');
    authStatus.classList.add('hidden');
    userInfo.classList.add('hidden');
    document.getElementById('todos-section').classList.add('hidden');
    emailInput.value = '';
    passwordInput.value = '';
    errorMessage.textContent = '';
}

// TODO LIST FUNCTIONS
const todoTitleInput = document.getElementById('todo-title');
const todoDescriptionInput = document.getElementById('todo-description');
const addTodoBtn = document.getElementById('add-todo-btn');
const todosList = document.getElementById('todos-list');

addTodoBtn.addEventListener('click', addTodo);
todoTitleInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') addTodo();
});

async function loadTodos() {
    try {
        const response = await fetch(\`\${API_URL}/todos\`, {
            credentials: 'include'
        });

        if (response.ok) {
            const todoItems = await response.json();
            renderTodos(todoItems);
        } else {
            console.error('Failed to load todos');
        }
    } catch (error) {
        console.error('Error loading todos:', error);
    }
}

function renderTodos(todoItems) {
    todosList.innerHTML = '';

    if (todoItems.length === 0) {
        todosList.innerHTML = '<div class="empty-state">No todos yet. Add one to get started!</div>';
        return;
    }

    todoItems.forEach(todo => {
        const todoEl = document.createElement('div');
        todoEl.className = \`todo-item \${todo.completed ? 'completed' : ''}\`;

        const date = new Date(todo.createdAt).toLocaleDateString();
        todoEl.innerHTML = \`
            <input type="checkbox" class="todo-checkbox" \${todo.completed ? 'checked' : ''}>
            <div class="todo-content">
                <div class="todo-title">\${escapeHtml(todo.title)}</div>
                \${todo.description ? \`<div class="todo-description">\${escapeHtml(todo.description)}</div>\` : ''}
                <div class="todo-date">Created: \${date}</div>
            </div>
            <div class="todo-actions">
                <button class="btn-delete">Delete</button>
            </div>
        \`;

        const checkbox = todoEl.querySelector('.todo-checkbox');
        checkbox.addEventListener('change', () => toggleTodo(todo.id, checkbox.checked));

        const deleteBtn = todoEl.querySelector('.btn-delete');
        deleteBtn.addEventListener('click', () => deleteTodo(todo.id));

        todosList.appendChild(todoEl);
    });
}

async function addTodo() {
    const title = todoTitleInput.value.trim();
    const description = todoDescriptionInput.value.trim();

    if (!title) {
        alert('Please enter a todo title');
        return;
    }

    try {
        const response = await fetch(\`\${API_URL}/todos\`, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ title, description })
        });

        if (response.ok) {
            todoTitleInput.value = '';
            todoDescriptionInput.value = '';
            loadTodos();
        } else {
            const error = await response.json();
            alert('Error creating todo: ' + (error.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error adding todo:', error);
        alert('Error creating todo');
    }
}

async function toggleTodo(id, completed) {
    try {
        const response = await fetch(\`\${API_URL}/todos/\${id}\`, {
            method: 'PUT',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ completed })
        });

        if (response.ok) {
            loadTodos();
        } else {
            console.error('Failed to update todo');
        }
    } catch (error) {
        console.error('Error updating todo:', error);
    }
}

async function deleteTodo(id) {
    if (!confirm('Are you sure you want to delete this todo?')) {
        return;
    }

    try {
        const response = await fetch(\`\${API_URL}/todos/\${id}\`, {
            method: 'DELETE',
            credentials: 'include'
        });

        if (response.ok) {
            loadTodos();
        } else {
            console.error('Failed to delete todo');
        }
    } catch (error) {
        console.error('Error deleting todo:', error);
    }
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Initialize
document.addEventListener('DOMContentLoaded', checkAuth);
    </script>
</body>
</html>`;

// Serve static files
router.get('/', () => {
  return new Response(HTML, {
    headers: { 'Content-Type': 'text/html' }
  });
});

// 404 handler
router.all('*', () => {
  return json({ error: 'Not found' }, { status: 404 });
});

export default router;
