# React.js Examples for User API Interaction

This document provides example React.js code snippets (functional components with hooks) for interacting with the user API. These examples assume JWT tokens are stored in HttpOnly cookies and are automatically sent by the browser with each request. The focus is on API calls and handling responses/errors.

**Base URL:** Assume all API calls are prefixed with your API's base URL (e.g., `const API_BASE_URL = '/api';` or `http://localhost:3000` if running on a different port than the frontend). For simplicity, the examples will use relative paths like `/users`.

---

## 1. Fetching All Users (GET `/users`)

This action is typically restricted to admin users in most applications.

```javascript
import React, { useState, useEffect } from 'react';

async function fetchAllUsers() {
  try {
    const response = await fetch('/users', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        // HttpOnly cookie with JWT is sent automatically by the browser
      },
    });

    if (!response.ok) {
      // Handle non-2xx responses
      const errorData = await response.json().catch(() => ({ message: 'Failed to fetch users and parse error JSON' }));
      throw new Error(`HTTP error! status: ${response.status}, message: ${errorData.error || response.statusText}`);
    }

    const users = await response.json();
    console.log('Fetched all users:', users);
    return users;
  } catch (error) {
    console.error('Error fetching all users:', error);
    // In a real app, set an error state here to display to the user
    throw error; // Re-throw to allow caller to handle if needed
  }
}

// Example Usage in a component
function UserList() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchAllUsers()
      .then(data => {
        setUsers(data);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  if (loading) return <p>Loading users...</p>;
  if (error) return <p>Error: {error}</p>;

  return (
    <div>
      <h2>User List (Admin)</h2>
      <ul>
        {users.map(user => (
          <li key={user.id}>{user.email} (ID: {user.id})</li>
        ))}
      </ul>
    </div>
  );
}

export default UserList;
```

---

## 2. Fetching a Specific User (GET `/users/:id`)

This can be used by a user to fetch their own data or by an admin to fetch any user's data. The backend authorization logic handles permissions.

```javascript
import React, { useState, useEffect } from 'react';

async function fetchUserById(userId) {
  try {
    const response = await fetch(`/users/${userId}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: 'Failed to fetch user and parse error JSON' }));
      throw new Error(`HTTP error! status: ${response.status}, message: ${errorData.error || response.statusText}`);
    }

    const user = await response.json();
    console.log(`Fetched user ${userId}:`, user);
    return user;
  } catch (error) {
    console.error(`Error fetching user ${userId}:`, error);
    throw error;
  }
}

// Example Usage (e.g., a user fetching their own profile)
function UserProfile({ userId }) { // userId would likely come from auth context or props
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (userId) {
      fetchUserById(userId)
        .then(data => {
          setUser(data);
          setLoading(false);
        })
        .catch(err => {
          setError(err.message);
          setLoading(false);
        });
    }
  }, [userId]);

  if (loading) return <p>Loading profile...</p>;
  if (error) return <p>Error: {error}</p>;
  if (!user) return <p>No user data.</p>;

  return (
    <div>
      <h2>User Profile</h2>
      <p>ID: {user.id}</p>
      <p>Email: {user.email}</p>
    </div>
  );
}

export default UserProfile;
```

---

## 3. Updating a User (PUT `/users/:id`)

Allows a user to update their own information (e.g., email). `userData` is an object with fields to update.

```javascript
import React, { useState } from 'react';

async function updateUser(userId, userData) { // userData = { email: "new.email@example.com" }
  try {
    const response = await fetch(`/users/${userId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(userData),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: 'Failed to update user and parse error JSON' }));
      throw new Error(`HTTP error! status: ${response.status}, message: ${errorData.error || response.statusText}`);
    }

    const updatedUser = await response.json();
    console.log(`Updated user ${userId}:`, updatedUser);
    return updatedUser;
  } catch (error) {
    console.error(`Error updating user ${userId}:`, error);
    throw error;
  }
}

// Example Usage
function UpdateUserForm({ userId }) {
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage('');
    setError('');
    try {
      const updatedUser = await updateUser(userId, { email });
      setMessage(`User updated successfully! New email: ${updatedUser.email}`);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h3>Update Your Email (User ID: {userId})</h3>
      <div>
        <label htmlFor="email">New Email:</label>
        <input
          type="email"
          id="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
      </div>
      <button type="submit">Update Email</button>
      {message && <p style={{ color: 'green' }}>{message}</p>}
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </form>
  );
}

export default UpdateUserForm;
```

---

## 4. Deleting a User (DELETE `/users/:id`)

Allows a user to delete their own account.

```javascript
import React, { useState } from 'react';

async function deleteUser(userId) {
  try {
    const response = await fetch(`/users/${userId}`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json', // Optional for DELETE if no body, but good practice
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: 'Failed to delete user and parse error JSON' }));
      throw new Error(`HTTP error! status: ${response.status}, message: ${errorData.error || response.statusText}`);
    }
    
    // DELETE typically returns a 200 OK with a success message or 204 No Content
    // Our API returns a JSON message for success.
    const result = await response.json(); 
    console.log(`User ${userId} deleted:`, result.message);
    return result;
  } catch (error) {
    console.error(`Error deleting user ${userId}:`, error);
    throw error;
  }
}

// Example Usage
function DeleteUserButton({ userId, onUserDeleted }) {
  const [isDeleting, setIsDeleting] = useState(false);
  const [error, setError] = useState('');

  const handleDelete = async () => {
    if (window.confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
      setIsDeleting(true);
      setError('');
      try {
        await deleteUser(userId);
        alert('Account deleted successfully.');
        if (onUserDeleted) onUserDeleted(); // Callback to update UI, e.g., logout
      } catch (err) {
        setError(err.message);
        setIsDeleting(false);
      }
    }
  };

  return (
    <div>
      <button onClick={handleDelete} disabled={isDeleting}>
        {isDeleting ? 'Deleting...' : 'Delete My Account'}
      </button>
      {error && <p style={{ color: 'red' }}>Error: {error}</p>}
    </div>
  );
}

export default DeleteUserButton;
```

---

## General Considerations

*   **Error Handling:**
    *   Always check `response.ok`. If it's `false`, the request failed.
    *   Attempt to parse the error response body as JSON (e.g., `await response.json()`), as APIs often return error details this way. Provide a fallback if JSON parsing fails.
    *   Handle network errors or other issues that might prevent the request from completing (the `catch` block of the `try...catch` statement).
    *   Different HTTP status codes (`response.status`) can be used to provide more specific feedback to the user (e.g., 401 for unauthorized, 403 for forbidden, 404 for not found, 409 for conflict).

*   **State Management:**
    *   In a real React application, you would use React's state (`useState`, `useReducer`) and lifecycle hooks (`useEffect`) to manage the data fetched from the API, loading indicators, and error messages.
    *   For more complex applications, a dedicated state management library like Context API, Redux, Zustand, or others would typically be used to handle global state, such as user authentication status and shared data.

*   **Authentication Context:**
    *   While HttpOnly cookies containing JWTs are handled automatically by the browser (sent with requests, not accessible via JavaScript), your React application still needs to be aware of the user's authentication status.
    *   This is usually managed by an "authentication context" or state. Upon successful login, the backend might return user information (excluding sensitive data like the token itself if it's in an HttpOnly cookie), which the React app can store.
    *   This context would provide information like `isAuthenticated` (boolean) and `currentUser` (object with user details like ID, email, role) to the rest of the application.
    *   This allows for conditional rendering of UI elements (e.g., showing "Login" vs. "Logout" buttons, protecting routes).
    *   The app would also need functions to trigger login (redirecting to a login page or making a login API call) and logout (making a logout API call which would invalidate the cookie/session on the backend, and then clearing client-side auth state).

*   **CSRF Tokens:**
    *   The Go backend in this project, using JWT in HttpOnly cookies, does not implement traditional CSRF token protection by default (as HttpOnly cookies are not accessible to JavaScript, mitigating some CSRF risks if "SameSite" attributes are properly set).
    *   If a backend *were* using CSRF tokens (e.g., in a session-based setup or alongside JWTs for specific reasons), the frontend would need to:
        1.  Fetch a CSRF token from a dedicated backend endpoint.
        2.  Include this token in a custom header (e.g., `X-CSRF-Token`) for all state-changing requests (POST, PUT, DELETE).
    *   This is mentioned for completeness but is not a direct concern for the current API setup if relying solely on HttpOnly JWT cookies with appropriate SameSite policies.

```
