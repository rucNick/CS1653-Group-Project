// Top-level imports
import React, { useState, useContext } from 'react';
import './Login.css';
import HomePage from './Home_page';
import Register from './Register';
import Adminpage from './Adminpage';
import { CryptoContext } from './App';

// Constants
const API_BASE_URL = 'http://localhost:5064';

// Component definition
const Login = () => {
    const crypto = useContext(CryptoContext);
    const [username, setUsername] = useState(""); 
    const [password, setPassword] = useState(""); 
    const [errorMessage, setErrorMessage] = useState(""); 
    const [isLoggedIn, setIsLoggedIn] = useState(false); 
    const [isRegistering, setIsRegistering] = useState(false);
    const [isAdmin, setIsAdmin] = useState(false);
    const [userData, setUserData] = useState({
        username: null,
        isVIP: false,
        isAdmin: false,
        groups: [],
        userID: null,
        isAuthenticated: false
    });
const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage("");

    try {
        // Debug logging
        console.log('Submitting with username:', username);

        // Input validation with early return
        if (!username || !username.trim()) {
            setErrorMessage("Username is required");
            return;
        }
        if (!password || !password.trim()) {
            setErrorMessage("Password is required");
            return;
        }

        // Ensure crypto context is available
        if (!crypto || !crypto.encrypt || !crypto.decrypt) {
            console.error('Crypto context not properly initialized');
            setErrorMessage("Security initialization failed. Please refresh the page.");
            return;
        }

        // Create login data object
        const loginData = {
            username: username.trim(),
            password: password.trim()
        };

        // Debug log before encryption
        console.log('Preparing to encrypt login data for user:', loginData.username);

        // Encrypt login data
        let encryptedData;
        try {
            encryptedData = await crypto.encrypt(loginData);
            
            // Validate encrypted data
            if (!encryptedData?.encrypted || !encryptedData?.iv || !encryptedData?.authTag) {
                throw new Error('Invalid encryption format');
            }

            // Debug log after encryption
            console.log('Successfully encrypted data:', {
                hasEncrypted: !!encryptedData.encrypted,
                hasIV: !!encryptedData.iv,
                hasAuthTag: !!encryptedData.authTag
            });

        } catch (encryptError) {
            console.error('Encryption error:', encryptError);
            setErrorMessage("Security error. Please try again.");
            return;
        }

        // Send request
        const response = await fetch(`${API_BASE_URL}/client/params`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify(encryptedData)
        });

        // Debug log response
        console.log('Server response status:', response.status);

        // Handle non-OK responses
        if (!response.ok) {
            const errorData = await response.json();
            console.error('Server error:', errorData);
            
            if (errorData.needsReconnect) {
                setErrorMessage("Session expired. Please refresh the page.");
                return;
            }
            
            if (errorData.encrypted) {
                try {
                    const decryptedError = await crypto.decrypt(errorData);
                    throw new Error(decryptedError.message || 'Authentication failed');
                } catch (decryptError) {
                    console.error('Error decrypting error message:', decryptError);
                    throw new Error('Authentication failed');
                }
            }
            throw new Error(errorData.error || 'Network response was not ok');
        }

        // Handle successful response
        const encryptedResponse = await response.json();
        console.log('Received encrypted response from server');
        
        // Decrypt response
        let decryptedData;
        try {
            decryptedData = await crypto.decrypt(encryptedResponse);
            console.log('Successfully decrypted response:', {
                isAuthenticated: decryptedData.isAuthenticated,
                username: decryptedData.username
            });
        } catch (decryptError) {
            console.error('Decryption error:', decryptError);
            throw new Error('Failed to process server response');
        }

        // Handle authentication result
        if (decryptedData.isAuthenticated) {
            setUserData({
                username: username, // Use the username from form input
                isVIP: decryptedData.isVIP || false,
                isAdmin: decryptedData.isAdmin || false,
                groups: decryptedData.groups || [],
                userID: decryptedData.userID,
                keys: decryptedData.postKeys,
                isAuthenticated: true,
            });

            setIsAdmin(decryptedData.isAdmin || false);
            setIsLoggedIn(true);
            setErrorMessage(""); // Clear any previous errors
        } else {
            setErrorMessage(decryptedData.message || "Authentication failed");
        }
    } catch (error) {
        console.error('Login error:', error);
        setErrorMessage(error.message || "An error occurred during authentication");
    }
    
    // Clear password for security but keep username for retry
    setPassword('');
};

    const handleGuestLogin = () => {
        setUserData({
            username: "Guest",
            isVIP: false,
            isAdmin: false,
            groups: ['guest'],
            userID: null,
            isAuthenticated: true
        });
        setIsLoggedIn(true);
    };

    const handleSignOut = async () => {
        try {
            const response = await fetch(`${API_BASE_URL}/client/logout`, {
                method: 'GET',
                credentials: 'include'
            });

            if (response.ok) {
                console.log('Signed out');
                setIsLoggedIn(false);
                setIsAdmin(false);
                setUserData({
                    username: null,
                    isVIP: false,
                    isAdmin: false,
                    groups: [],
                    userID: null,
                    isAuthenticated: false
                });
            } else {
                throw new Error('Logout failed');
            }
        } catch (error) {
            console.error('Error during logout:', error);
            setErrorMessage("An error occurred during logout. Please try again later.");
        }
    };

    const handleRegisterSuccess = () => {
        setIsRegistering(false);
    };

    const handleGoBackToLogin = () => {
        setIsRegistering(false);
    };

    const handleInputFocus = (field) => {
        if (errorMessage) {
            if (field === 'username') {
                setUsername("");
            } else if (field === 'password') {
                setPassword("");
            }
            setErrorMessage("");
        }
    };

    // Render logic
    if (isAdmin) {
        return <Adminpage />;
    }

    if (isLoggedIn) {
        return (
            <HomePage
                username={userData.username}
                isVIP={userData.isVIP}
                onSignOut={handleSignOut}
                groups={userData.groups}
                userID={userData.userID}
                keys={userData.keys}
            />
        );
    }

    if (isRegistering) {
        return (
            <Register
                onRegisterSuccess={handleRegisterSuccess}
                onGoBackToLogin={handleGoBackToLogin}
            />
        );
    }

    return (
        <div className="login-page">
            <h1 className="site-title">CYPHERSPACE</h1>
            <div className="login-container">
                <form className="login-form" onSubmit={handleSubmit}>
                    <h2>Login</h2>
                    
                    <div className="input-group">
                        <label htmlFor="username">Username</label>
                        <input
                            type="text"
                            id="username"
                            placeholder="Enter your username"
                            value={username}
                            onFocus={() => handleInputFocus('username')}
                            onChange={(e) => setUsername(e.target.value)}
                            required
                        />
                    </div>

                    <div className="input-group">
                        <label htmlFor="password">Password</label>
                        <input
                            type="password"
                            id="password"
                            placeholder="Enter your password"
                            value={password}
                            onFocus={() => handleInputFocus('password')}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                        />
                    </div>

                    <button type="submit" className="login-btn">Login</button>

                    {errorMessage && <p className="error-message">{errorMessage}</p>}
                </form>

                <div className="login-options">
                    <p className="create-account">
                        <a href="/#" onClick={() => setIsRegistering(true)}>Create a new account</a>
                    </p>
                    <span className="divider">|</span>
                    <p className="guest-login">
                        <a href="/#" onClick={handleGuestLogin}>Guest</a>
                    </p>
                </div>
            </div>
        </div>
    );
};

export default Login;