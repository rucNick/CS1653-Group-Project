import React, { useEffect, useState } from 'react';
import { verifyServer } from './serverAuth';
import './App.css';  // 如果需要全局样式
import Login from './Login';  // 导入 Login 组件
import { Buffer } from 'buffer'

// Crypto functions for T4
const deriveKey = async (sharedSecret) => {
  // Use HKDF with shared secret to derive AES key
  const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      sharedSecret,
      "HKDF",
      false,
      ["deriveBits"]
  );
  const typedArray1 = new Int8Array(0)
  return await window.crypto.subtle.deriveBits(
      {
          name: "HKDF",
          hash: "SHA-256",
          salt: typedArray1,
          length: 256,  // for AES-256
          info: typedArray1
      },
      keyMaterial,
      256
  );
};
// Context to share encryption functions
export const CryptoContext = React.createContext(null);


function App() {
  const [isServerVerified, setIsServerVerified] = useState(false);
  const [error, setError] = useState(null);
  const [cryptoFunctions, setCryptoFunctions] = useState(null);

  useEffect(() => {
    const verifyConnection = async () => {
        try {
            const result = await verifyServer('http://localhost:5064');
            if (result.verified) {
                const aesKey = await deriveKey(result.sharedSecret);   
                const encrypt = async (data) => {
                    // Generate IV
                    const iv = window.crypto.getRandomValues(new Uint8Array(16));
                    
                    // Import key for AES
                    const key = await window.crypto.subtle.importKey(
                        "raw",
                        aesKey,
                        { name: "AES-GCM" },
                        false,
                        ["encrypt"]
                    );

                    // Encrypt
                    const encoded = new TextEncoder().encode(JSON.stringify(data));
                    const encrypted = await window.crypto.subtle.encrypt(
                        { name: "AES-GCM", iv },
                        key,
                        encoded
                    );

                    // NEW: Get auth tag (last 16 bytes of encrypted data)
                    const encryptedArray = new Uint8Array(encrypted);
                    const authTag = encryptedArray.slice(-16); // GCM auth tag is 16 bytes
                    const ciphertext = encryptedArray.slice(0, -16);

                    

                    // Return both encrypted data and IV
                    return {
                        encrypted: Buffer.from(ciphertext).toString('base64'),
                        iv: Buffer.from(iv).toString('base64'),
                        authTag: Buffer.from(authTag).toString('base64')
                    };
                };

                const decrypt = async (encryptedData) => {
                    try {
                        // Import key for AES
                        const key = await window.crypto.subtle.importKey(
                            "raw",
                            aesKey,
                            { name: "AES-GCM" },
                            false,
                            ["decrypt"]
                        );
                        // Combine ciphertext and auth tag
                        const ciphertext = Buffer.from(encryptedData.encrypted, 'base64');
                        const authTag = Buffer.from(encryptedData.authTag, 'base64');
                        const combined = new Uint8Array([...ciphertext, ...authTag]);
                        // Decrypt
                        const decrypted = await window.crypto.subtle.decrypt(
                            {
                                name: "AES-GCM",
                                iv: Buffer.from(encryptedData.iv, 'base64')
                            },
                            key,
                            combined
                        );

                        // Parse result
                        return JSON.parse(new TextDecoder().decode(decrypted));
                    } catch (error) {
                        console.error('Decryption failed:', error);
                        throw error;
                    }
                };

                setCryptoFunctions({ encrypt, decrypt });
                setIsServerVerified(true);
            } else {
                setError(result.error);
            }
        } catch (error) {
            setError('Server verification failed: ' + error.message);
        }
    };

    verifyConnection();
  }, []);

  if (error) {
    return <div>Error: {error}</div>;
  }

  if (!isServerVerified) {
    return <div>Verifying server identity...</div>;
  }


  return (
    <div className="App">
      <CryptoContext.Provider value={cryptoFunctions}>
          <Login />
      </CryptoContext.Provider>
    </div>
  );
}

export default App;
