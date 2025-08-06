
import { Buffer } from 'buffer'

// serverAuth.js

// Store fingerprint in localStorage
const FINGERPRINT_KEY = 'server_fingerprint';

// Function to generate fingerprint from public key
const generateFingerprint = async (publicKey) => {
    const msgBuffer = new TextEncoder().encode(publicKey);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgBuffer);
    return Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
};

const generateECDHKeys = async () => {
    try {
        // Generate ECDH key pair
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-256"
            },
            true,  // extractable
            ["deriveKey", "deriveBits"]
        );

        // Export public key to send to server
        const publicKeyBuffer = await window.crypto.subtle.exportKey(
            "raw",
            keyPair.publicKey
        );

        return {
            privateKey: keyPair.privateKey,
            publicKey: publicKeyBuffer,
            originalPublicKey: keyPair.publicKey
        };
    } catch (error) {
        console.error('ECDH Key generation failed:', error);
        throw error;
    }
};

const generateChallenge = () => {
    const array = new Uint8Array(32);
    window.crypto.getRandomValues(array);
    return array;
};

const verifySignature = async (data, signature, publicKey) => {
    try {
        // Convert PEM to ArrayBuffer
        // Remove header/footer and convert base64 to binary
        const pemHeader = '-----BEGIN PUBLIC KEY-----';
        const pemFooter = '-----END PUBLIC KEY-----';
        const pemContents = publicKey
            .replace(pemHeader, '')
            .replace(pemFooter, '')
            .replace(/\s/g, '');
        
        const binaryKey = Buffer.from(pemContents, 'base64');

        // Import RSA public key for verification
        const cryptoKey = await window.crypto.subtle.importKey(
            'spki',
            binaryKey,
            {
                name: 'RSASSA-PKCS1-v1_5',
                hash: 'SHA-256'
            },
            false,
            ['verify']
        );

        // Verify signature
        return await window.crypto.subtle.verify(
            'RSASSA-PKCS1-v1_5',
            cryptoKey,
            Buffer.from(signature, 'base64'),
            data
        );
    } catch (error) {
        console.error('Signature verification failed:', error);
        return false;
    }
};

const verifyServer = async (serverUrl) => {
    try {
        // Step 1: Get server's public key
        console.log(1)
        const identityResponse = await fetch(`${serverUrl}/server-identity`);
        const { publicKey } = await identityResponse.json();

        // Generate fingerprint from public key
        const fingerprint = await generateFingerprint(publicKey);

        // Step 2: Generate ECDH keys and challenge
        console.log(2)
        const { publicKey: ecdhPublicKey, privateKey: ecdhPrivateKey } = await generateECDHKeys();
        const challenge = generateChallenge();

        // Step 3: Send challenge and ECDH public key
        console.log(3)
        const challengeResponse = await fetch(`${serverUrl}/verify-identity`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                challenge: Buffer.from(challenge).toString('base64'),
                ecdhPublicKey: Buffer.from(ecdhPublicKey).toString('base64')
            })
        });

        const { ecdhServerPublic, signature } = await challengeResponse.json();

        // Step 4: Verify signature
        console.log(4)
        const dataToVerify = new Uint8Array([
            ...challenge,
            ...new Uint8Array(ecdhPublicKey),
            ...Buffer.from(ecdhServerPublic, 'base64')
        ]);

        const isSignatureValid = await verifySignature(
            dataToVerify,
            signature,
            publicKey
        );

        if (!isSignatureValid) {
            throw new Error('Server signature verification failed');
        }

        // Step 5: Check/store fingerprint
        console.log(5)
        const storedFingerprint = localStorage.getItem(FINGERPRINT_KEY);
        
        if (!storedFingerprint) {
            // First connection
            const userConfirmed = await showFingerprintVerification(fingerprint);
            if (!userConfirmed) {
                throw new Error('User rejected fingerprint');
            }
            localStorage.setItem(FINGERPRINT_KEY, fingerprint);
        } else if (storedFingerprint !== fingerprint) {
            throw new Error('Server fingerprint mismatch!');
        }

        // Import server's public key for ECDH
        console.log(6)
        const serverPublicKey = await window.crypto.subtle.importKey(
            "raw",
            Buffer.from(ecdhServerPublic, 'base64'),
            {
                name: "ECDH",
                namedCurve: "P-256"
            },
            true,
            []
        );

        // Derive shared secret
        console.log(7)
        const sharedSecret = await window.crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: serverPublicKey
            },
            ecdhPrivateKey,
            256
        );

        return {
            verified: true,
            sharedSecret: new Uint8Array(sharedSecret),
            ecdhKeys: { publicKey: ecdhPublicKey, privateKey: ecdhPrivateKey }
        };
    } catch (error) {
        console.error('Server verification failed:', error);
        return { verified: false, error: error.message };
    }
};

const showFingerprintVerification = (fingerprint) => {
    return new Promise((resolve) => {
        const formattedFingerprint = fingerprint.match(/.{2}/g).join(':');
        
        const message = `
            CRITICAL SECURITY VERIFICATION
            
            Server has proven possession of private key.
            Server Fingerprint: ${formattedFingerprint}
            
            You MUST verify this matches the official fingerprint from:
            - Official documentation: [URL]
            
            This fingerprint will be used to verify the server's
            identity in all future connections.
            
            WARNING: Proceeding without verification risks security breach
            
            Does this fingerprint match the official source? (yes/no)
        `;

        const userConfirmed = window.confirm(message);
        resolve(userConfirmed);
    });
};

export { verifyServer };