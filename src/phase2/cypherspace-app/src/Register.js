import React, { useState, useContext } from 'react';
import './Register.css';
import { CryptoContext } from './App'; // Import CryptoContext

const Register = ({ onRegisterSuccess, onGoBackToLogin }) => {
    const crypto = useContext(CryptoContext); // Access encryption utilities
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [vipCode, setVipCode] = useState("");
    const [errorMessage, setErrorMessage] = useState("");

    const validatePassword = (password) => {
        const lengthRequirement = password.length >= 8;
        const complexityRequirement = /[A-Za-z]/.test(password) && /[^A-Za-z]/.test(password);
        return lengthRequirement && complexityRequirement;
    };

const handleSubmit = async (e) => {
    e.preventDefault();

    setErrorMessage(""); // Clear previous error messages

    if (password !== confirmPassword) {
        setErrorMessage("Passwords do not match.");
        return;
    }

    if (!validatePassword(password)) {
        setErrorMessage("Password must be at least 8 characters long and include letters and numbers or symbols.");
        return;
    }

    try {
        // Ensure crypto context is available
        if (!crypto || !crypto.encrypt || !crypto.decrypt) {
            console.error("Crypto context not properly initialized");
            setErrorMessage("Security initialization failed. Please refresh the page.");
            return;
        }

        // Prepare registration data
        const registrationData = {
            username: username.trim(),
            password: password.trim(),
            vipCode: vipCode || ""
        };

        // Encrypt registration data
        let encryptedData;
        try {
            encryptedData = await crypto.encrypt(registrationData);
            if (!encryptedData?.encrypted || !encryptedData?.iv || !encryptedData?.authTag) {
                throw new Error("Invalid encryption format");
            }
        } catch (encryptError) {
            console.error("Encryption error:", encryptError);
            setErrorMessage("Security error. Please try again.");
            return;
        }

        // Send encrypted data to the bridge server
        const response = await fetch("http://localhost:5064/client/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            credentials: "include",
            body: JSON.stringify(encryptedData)
        });

        // Handle server response
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Server error:", errorData);

            if (errorData.needsReconnect) {
                setErrorMessage("Session expired. Please refresh the page.");
                return;
            }

            if (errorData.encrypted) {
                try {
                    const decryptedError = await crypto.decrypt(errorData);
                    throw new Error(decryptedError.message || "Registration failed");
                } catch (decryptError) {
                    console.error("Error decrypting error message:", decryptError);
                    throw new Error("Registration failed");
                }
            }
            throw new Error(errorData.error || "Network response was not ok");
        }

        // Decrypt server response
        const encryptedResponse = await response.json();
        let decryptedData;
        try {
            decryptedData = await crypto.decrypt(encryptedResponse);
        } catch (decryptError) {
            console.error("Decryption error:", decryptError);
            throw new Error("Failed to process server response");
        }

        // Handle success or error
        if (decryptedData.success) {
            setErrorMessage("");
            onRegisterSuccess();
        } else {
            setErrorMessage(decryptedData.message || "Registration failed");
        }
    } catch (error) {
        console.error("Registration error:", error);
        setErrorMessage(error.message || "An error occurred during registration");
    }
};


    return (
        <div className="register-page">
            <h1 className="site-title">New Account</h1>
            <div className="register-container">
                <form className="register-form" onSubmit={handleSubmit}>
                    <div className="input-group">
                        <label htmlFor="username">Create Username</label>
                        <input
                            type="text"
                            id="username"
                            placeholder="eg. XXX123 (Pitt ID)"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            required
                        />
                    </div>

                    <div className="input-group">
                        <label htmlFor="password">Create Password</label>
                        <input
                            type="password"
                            id="password"
                            placeholder="At least 8 characters, letters and numbers/symbols"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                        />
                    </div>

                    <div className="input-group">
                        <label htmlFor="confirmPassword">Confirm Password</label>
                        <input
                            type="password"
                            id="confirmPassword"
                            placeholder="Confirm your password"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            required
                        />
                    </div>

                    <div className="input-group">
                        <label htmlFor="vipCode">Got a VIP redemption code? Please enter below:</label>
                        <input
                            type="text"
                            id="vipCode"
                            placeholder="Enter VIP Code"
                            value={vipCode}
                            onChange={(e) => setVipCode(e.target.value)}
                        />
                    </div>

                    <button type="submit" className="register-btn">Register</button>

                    {errorMessage && (
                        <p className="error-message">
                            {errorMessage}
                        </p>
                    )}
                </form>

                <div className="go-back-login">
                    <h4>Already have an account?</h4>
                    <a href="/#" onClick={onGoBackToLogin}>Go back to Login</a>
                </div>
            </div>
        </div>
    );
};

export default Register;
