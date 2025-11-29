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
        const response = await fetch(`${API_URL}/verify`, {
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
        const response = await fetch(`${API_URL}/login`, {
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
        await fetch(`${API_URL}/logout`, {
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

    statusMessage.textContent = `✓ Successfully authenticated as ${user.email}`;
    userDataDiv.textContent = JSON.stringify(user, null, 2);
}

// Show login form
function showLoginForm() {
    loginForm.classList.remove('hidden');
    authStatus.classList.add('hidden');
    userInfo.classList.add('hidden');
    emailInput.value = '';
    passwordInput.value = '';
    errorMessage.textContent = '';
}

// Initialize
document.addEventListener('DOMContentLoaded', checkAuth);
