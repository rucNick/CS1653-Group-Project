const express = require('express');
const cors = require('cors');
const axios = require('axios');
const session = require('express-session');
const app = express();
const crypto = require('crypto');
const fs = require('fs').promises;
require('dotenv').config();

let resourceLocation = 2
let authLocation = 3

const resourceServerBaseUrl = `http://localhost:4064`;
const authServerBaseUrl = `http://localhost:8064`;

// Global variables for keys
let privateKey, publicKey;

// Middleware setup
app.use(express.json());
app.use(cors({
    origin: ['http://localhost:3064', 'http://localhost:3000', 'http://localhost:4000', 'http://localhost:3065', 'http://acns-02.cs.pitt.edu:3064', 'http://acns-03.cs.pitt.edu:3064', 'http://acns-03.cs.pitt.edu:3065', 'http://acns-03.cs.pitt.edu:3000', 'http://acns-02.cs.pitt.edu:3065', 'http://acns-02.cs.pitt.edu:3000', 'http://acns-02.cs.pitt.edu:4000'],
    credentials: true
}));

app.use(session({
    secret: '7c4jsena70lryi5n824d',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: true }
}));

// Session verification middleware
const verifySession = (req, res, next) => {
    if (!req.session) {
        console.error('No session found');
        return res.status(440).json({ error: 'Session expired' });
    }
    next();
};

// ECDH verification middleware
const verifyECDH = (req, res, next) => {
    if (!req.session?.ecdhParams?.aesKey?.data) {
        console.error('No encryption parameters found');
        return res.status(401).json({ error: 'Encryption not initialized' });
    }
    next();
};

// Authentication verification middleware
const verifyAuth = (req, res, next) => {
    // Skip auth check for guest routes
    if (req.path === '/bridge/guest') {
        return next();
    }

    if (!req.session?.resourceServerObj?.isAuthenticated) {
        console.error('User not authenticated');
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
};

// ============= RESOURCE SERVER AUTHENTICATION CODE START =============
// Store Resource Server fingerprint in memory (not localStorage like client does)
let resourceServerFingerprint = null;


const generateECDHKeys2 = () => {
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    return {
        privateKey: ecdh.getPrivateKey(),
        publicKey: ecdh.getPublicKey(),
        ecdh: ecdh
    };
};

const verifyResourceServer = async(resourceServerUrl) => {
    try {
        // Step 1: Get Resource Server's RSA public key and fingerprint
        const identityResponse = await axios.get(`${resourceServerUrl}/server-identity`);
        const { publicKey: rsaPublicKey, fingerprint } = identityResponse.data;

        if (!rsaPublicKey || !fingerprint) {
            throw new Error('Invalid server identity response');
        }

        // Step 2: Verify fingerprint
        if (!resourceServerFingerprint) {
            // First connection
            const expectedFingerprint = process.env.RESOURCE_SERVER_FINGERPRINT;
            if (!expectedFingerprint) {
                throw new Error('Resource Server fingerprint not configured');
            }

            console.log('\n=== CRITICAL SECURITY VERIFICATION ===');
            console.log('Server has presented fingerprint:', fingerprint);
            console.log('Expected fingerprint:', expectedFingerprint);
            console.log('==========================================\n');

            if (fingerprint !== expectedFingerprint) {
                console.error('Fingerprint mismatch!');
                console.error('Received:', fingerprint);
                console.error('Expected:', expectedFingerprint);
                throw new Error('Resource Server fingerprint mismatch - possible impersonation attempt');
            }

            resourceServerFingerprint = fingerprint;
            console.log('Fingerprint verified and stored successfully');
        } else {
            if (resourceServerFingerprint !== fingerprint) {
                console.error('Fingerprint changed!');
                console.error('Stored:', resourceServerFingerprint);
                console.error('Received:', fingerprint);
                throw new Error('Resource Server fingerprint changed - possible MITM attack');
            }
            console.log('Resource Server fingerprint verified');
        }

        // Step 3: Generate challenge and ECDH keypair
        const challenge = crypto.randomBytes(32);
        const keys = generateECDHKeys2();

        console.log('Generated ECDH key pair');

        // Step 4: Send challenge and ECDH public key
        const verifyResponse = await axios.post(
            `${resourceServerUrl}/verify-identity`, {
                challenge: challenge.toString('base64'),
                ecdhPublicKey: keys.publicKey.toString('base64')
            }, {
                headers: { 'Content-Type': 'application/json' }
            }
        );

        const { ecdhServerPublic, signature } = verifyResponse.data;

        // Step 5: Verify RSA signature
        const dataToVerify = Buffer.concat([
            challenge,
            keys.publicKey,
            Buffer.from(ecdhServerPublic, 'base64')
        ]);

        const verify = crypto.createVerify('SHA256');
        verify.update(dataToVerify);
        const isValid = verify.verify(
            `-----BEGIN PUBLIC KEY-----\n${rsaPublicKey}\n-----END PUBLIC KEY-----`,
            Buffer.from(signature, 'base64')
        );

        if (!isValid) {
            throw new Error('Invalid server signature');
        }

        console.log('Server signature verified successfully');

        // Step 6: Compute shared secret
        let sharedSecret;
        try {
            const serverPublicKey = Buffer.from(ecdhServerPublic, 'base64');
            console.log('Computing shared secret...');
            sharedSecret = keys.ecdh.computeSecret(serverPublicKey);
            console.log('Shared secret computed successfully');
        } catch (error) {
            console.error('Error computing shared secret:', error);
            throw error;
        }

        // Change shared secret for GCM
        const finalKey = crypto.hkdfSync(
            'sha256',
            sharedSecret,
            Buffer.alloc(0), // empty salt
            Buffer.alloc(0), // empty info
            32 // 32 bytes for AES-256
        );
        console.log('Key exchange completed successfully');

        return {
            verified: true,
            sharedSecret: finalKey,
            rsaPublicKey,
            fingerprint: resourceServerFingerprint
        };

    } catch (error) {
        console.error('Resource Server verification failed:', error);
        throw error;
    }
};

// Initialize Resource Server verification
async function initializeResourceServerAuth() {
    try {
        console.log('Starting Resource Server verification...');

        const result = await verifyResourceServer(resourceServerBaseUrl);
        if (!result.verified) {
            throw new Error('Failed to verify Resource Server');
        }

        console.log('Resource Server verified successfully');

        // Store shared secret for T4
        global.resourceServerSecret = result.sharedSecret;

        return true;
    } catch (error) {
        console.error('Resource Server verification failed:', error);
        throw error;
    }
}


// ============= RESOURCE SERVER AUTHENTICATION CODE END =============

 //============= Auth SERVER  CODE =============
let authServerSecret = null;
let authAxiosInstance = null;

const createAuthServerInstance = () => {
    // Create axios instance with proper cookie handling
    const instance = axios.create({
        baseURL: authServerBaseUrl,
        withCredentials: true,
        headers: {
            'Content-Type': 'application/json'
        }
    });
    
    // Add cookie handling interceptor
    instance.interceptors.request.use(config => {
        // Ensure cookies are sent with requests
        config.withCredentials = true;
        return config;
    });

    // Store cookies from responses
    instance.interceptors.response.use(
        response => {
            const cookies = response.headers['set-cookie'];
            if (cookies) {
                // Store cookies for future requests
                instance.defaults.headers.Cookie = cookies.join('; ');
            }
            return response;
        },
        error => {
            return Promise.reject(error);
        }
    );

    return instance;
};

// Modified initialization function
async function initializeAuthServerEncryption() {
    try {
        console.log('Starting Auth Server encryption initialization...');
        
        // Create persistent axios instance
        const authAxios = createAuthServerInstance();
        
        // Step 1: Get server's public key
        const authServerECPublic = await authAxios.post('/initiate-key-exchange');
        console.log('Server public key received:', authServerECPublic.data);
        

        // Step 2: Generate our keys
        const ecdh = crypto.createECDH('prime256v1');
        ecdh.generateKeys();
        const publicKey = ecdh.getPublicKey();

        // Step 3: Complete key exchange using same instance
        const completeExchange = await authAxios.post('/complete-key-exchange', {
            clientPublicKey: publicKey.toString('base64')
        });

        if (completeExchange.data.status === 'success') {
            // Step 4: Generate shared secret
            const serverPubKeyData = Buffer.from(authServerECPublic.data.serverPublicKey, 'base64');
            const key = crypto.createPublicKey({
                key: serverPubKeyData,
                format: 'der',
                type: 'spki'
            });

            const rawKey = key.export({ format: 'jwk' });
            const x = Buffer.from(rawKey.x, 'base64url');
            const y = Buffer.from(rawKey.y, 'base64url');
            
            const rawPublicKey = Buffer.concat([
                Buffer.from([0x04]), // Uncompressed point format
                x,
                y
            ]);

            const sharedSecret = ecdh.computeSecret(rawPublicKey);

            // Use HKDF instead of plain SHA-256
            const finalKey = crypto.hkdfSync(
                'sha256',
                sharedSecret,
                Buffer.alloc(0), // empty salt
                Buffer.alloc(0), // empty info
                32  // 32 bytes for AES-256
            );
            
            // Store auth server connection data
            authServerSecret = finalKey;
            authAxiosInstance = authAxios;

            // Verify key exchange
            try {
                const testResponse = await authAxios.get('/test-key');
                if (testResponse.data.status !== 'success') {
                    throw new Error('Key exchange verification failed');
                }
                console.log('Key exchange verified successfully');
                return true;
            } catch (error) {
                console.error('Key exchange verification failed:', error.response?.data);
                throw error;
            }
        }
        
        throw new Error('Key exchange failed - unsuccessful status');
    } catch (error) {
        console.error('Failed to initialize Auth Server encryption:', error);
        throw error;
    }
}

// Update authT4 function as well
const authT4 = async() => {
    try {
        // Get server's public key
        const authServerECPublic = await axios.post(
            `${authServerBaseUrl}/initiate-key-exchange`, { hi: 'hello' }, {
                headers: {
                    'Content-Type': 'application/json',
                }
            }
        );
        console.log('Server public key received:', authServerECPublic.data);

        // Generate our ECDH instance and keys
        const ecdh = crypto.createECDH('prime256v1');
        ecdh.generateKeys();

        const publicKey = ecdh.getPublicKey(); // Gets the raw public key

        // Send our public key
        const completeExchange = await axios.post(
            `${authServerBaseUrl}/complete-key-exchange`, { clientPublicKey: publicKey.toString('base64') }, {
                headers: {
                    'Content-Type': 'application/json',
                }
            }
        );
        console.log('Key exchange response:', completeExchange.data);

        // Store the shared secret if needed
        if (completeExchange.data.status === 'success') {
            try {
                // Convert server's SPKI public key to raw format
                const serverPubKeyData = Buffer.from(authServerECPublic.data.serverPublicKey, 'base64');
                const key = crypto.createPublicKey({
                    key: serverPubKeyData,
                    format: 'der',
                    type: 'spki'
                });

                // Extract the raw public key point
                const rawKey = key.export({ format: 'jwk' });
                const x = Buffer.from(rawKey.x, 'base64url');
                const y = Buffer.from(rawKey.y, 'base64url');

                // Create uncompressed point format (0x04 || x || y)
                const rawPublicKey = Buffer.concat([
                    Buffer.from([0x04]),
                    x,
                    y
                ]);

                // Compute shared secret using the raw public key
                const sharedSecret = ecdh.computeSecret(rawPublicKey);

                // Use HKDF to derive final key
                const finalKey = crypto.hkdfSync(
                    'sha256',
                    sharedSecret,
                    Buffer.alloc(0), // empty salt
                    Buffer.alloc(0), // empty info
                    32 // 32 bytes for AES-256
                );


                return finalKey;
            } catch (error) {
                console.error('Error computing shared secret:', error);
                throw error;
            }
        }

    } catch (error) {
        if (error.response) {
            console.error('Server error:', error.response.data);
        } else {
            console.error('Error:', error.message);
        }
        throw error;
    }
};

// Key management functions
const loadServerKeys = async() => {
    try {
        const privateKeyData = await fs.readFile('private_key.pem', 'utf8');
        const publicKeyData = await fs.readFile('public_key.pem', 'utf8');
        return {
            privateKey: privateKeyData,
            publicKey: publicKeyData
        };
    } catch {
        // Generate new keys if they don't exist
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 4096,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });

        // Store keys for persistence across restarts
        await fs.writeFile('private_key.pem', privateKey);
        await fs.writeFile('public_key.pem', publicKey);
        return { privateKey, publicKey };
    }
};


const generateECDHKeys = () => {
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    return {
        privateKey: ecdh.getPrivateKey(),
        publicKey: ecdh.getPublicKey()
    };
};

const signData = (data, privateKey) => {
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    return sign.sign(privateKey, 'base64');
};

const decryptWithGCM = (encryptedData, key) => {
    try {
        // Convert base64 strings to buffers
        const encryptedBuffer = Buffer.from(encryptedData.encrypted, 'base64');
        const ivBuffer = Buffer.from(encryptedData.iv, 'base64');
        const authTagBuffer = Buffer.from(encryptedData.authTag, 'base64');
        // Create decipher
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            key,
            ivBuffer
        );

        // Set auth tag
        decipher.setAuthTag(authTagBuffer);

        // Decrypt
        let decrypted = decipher.update(encryptedBuffer);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        // Return as UTF-8 string
        return decrypted.toString('utf8');
    } catch (error) {
        console.error('Decryption failed:', error);
        throw new Error('Failed to decrypt data');
    }
};

const encryptWithGCM = (plaintext, key) => {
    try {
        // Generate a random IV (Initialization Vector)
        const iv = crypto.randomBytes(16);

        // Create cipher
        const cipher = crypto.createCipheriv(
            'aes-256-gcm',
            key,
            iv
        );

        // Encrypt the plaintext
        let encrypted = cipher.update(JSON.stringify(plaintext), 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        // Get auth tag
        const authTag = cipher.getAuthTag();

        // Return everything as base64 strings
        return {
            encrypted: encrypted.toString('base64'),
            iv: iv.toString('base64'),
            authTag: authTag.toString('base64')
        };
    } catch (error) {
        console.error('Encryption failed:', error);
        throw new Error('Failed to encrypt data');
    }
};
//---------------------End of Auth server T4-------------------------------


// Initialize server
async function initializeServer() {
    try {
        const keys = await loadServerKeys();
        privateKey = keys.privateKey;
        publicKey = keys.publicKey;
        console.log('Server keys loaded successfully');
    } catch (error) {
        console.error('Failed to initialize server identity module:', error);
        process.exit(1); // Cannot start without keys
    }
}

// T3 Routes (before middleware)
app.get('/server-identity', (req, res) => {
    res.json({
        publicKey
    });
});

app.post('/verify-identity', async(req, res) => {
    try {
        const { challenge, ecdhPublicKey } = req.body;

        // Decode base64 values from client
        const clientChallenge = Buffer.from(challenge, 'base64');
        const clientECDHPublic = Buffer.from(ecdhPublicKey, 'base64');

        // Generate server's ECDH keys
        const serverECDH = generateECDHKeys();

        // Compute shared secret
        const sharedSecret = crypto.createECDH('prime256v1');
        sharedSecret.setPrivateKey(serverECDH.privateKey);
        const derivedSecret = sharedSecret.computeSecret(clientECDHPublic);

        // HKDF to derive AES key
        const aesKey = crypto.hkdfSync(
            'sha256',
            derivedSecret,
            Buffer.alloc(0), // empty salt
            Buffer.alloc(0), // empty info
            32 // 32 bytes for AES-256
        );

        aesObj = Buffer.from(aesKey)
        aesObjData = aesObj.data

        // Store ECDH parameters in session for T4
        if (req.session) {
            req.session.ecdhParams = {
                privateKey: serverECDH.privateKey,
                publicKey: serverECDH.publicKey,
                sharedSecret: derivedSecret,
                aesKey: aesObj
            };
        }

        // Sign the concatenated data
        const dataToSign = Buffer.concat([
            clientChallenge,
            clientECDHPublic,
            Buffer.from(serverECDH.publicKey)
        ]);

        const signature = signData(dataToSign, privateKey);

        // Send response
        res.json({
            ecdhServerPublic: serverECDH.publicKey,
            signature
        });
    } catch (error) {
        console.error('Error in verify-identity:', error);
        res.status(500).json({
            error: 'Failed to process identity verification'
        });
    }
});


app.get('/', (req, res) => {
    res.send('Connected to bridge');
});

app.get('/bridge/guest', async (req, res) => {
    try {
        if (!req.session.resourceServerObj) {
            req.session.resourceServerObj = {
                isAuthenticated: false,
                username: 'Guest',
                groups: ['guest'],
                userID: null,
                isVIP: false,
                isAdmin: false,
                postKeys: null
            };

            await new Promise((resolve, reject) => {
                req.session.save((err) => {
                    if (err) {
                        console.error('Session save error:', err);
                        reject(err);
                    } else {
                        resolve();
                    }
                });
            });
        }

        console.log('Guest session initialized:', req.session.resourceServerObj);

        const response = await axios.get(`${resourceServerBaseUrl}/getGuestPosts`, {
            headers: { 'Content-Type': 'application/json' },
        });

        // Extract the encrypted data from the response
        const encryptedData = response.data.encryptedData;
        
        if (!encryptedData) {
            console.error('No encrypted data received from resource server');
            return res.status(500).json({ error: 'Invalid response format' });
        }

        // Decrypt the data
        const decryptedString = decryptWithGCM(
            encryptedData,
            Buffer.from(global.resourceServerSecret)
        );

        // Parse the decrypted JSON string into an array
        const guestPosts = JSON.parse(decryptedString);


        res.json(guestPosts);
    } catch (error) {
        console.error('Error fetching guest posts:', error);

        if (error.response) {
            return res.status(error.response.status).json({
                error: error.response.data?.message || 'Failed to fetch guest posts',
            });
        }

        res.status(500).json({ error: 'Internal server error' });
    }
});


app.get('/bridge/posts', verifySession, verifyAuth, async (req, res) => {
    try {
        if (!global.resourceServerSecret) {
            console.error('Resource server secret not initialized');
            return res.status(500).json(encryptWithGCM(
                { error: 'Server configuration error' },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            ));
        }

        console.log('Fetching posts for authenticated user:', req.session.resourceServerObj);

        // Encrypt request for resource server
        const requestBody = {
            trueParams: req.session.resourceServerObj.trueParams
        };

        const resourceSecret = Buffer.isBuffer(global.resourceServerSecret) ? 
            global.resourceServerSecret : 
            Buffer.from(global.resourceServerSecret);

        // Format the encrypted request correctly
        const encryptedData = encryptWithGCM(requestBody, resourceSecret);
        
        // Send the encrypted data in the expected format
        const formattedRequest = {
            encrypted: encryptedData.encrypted,
            iv: encryptedData.iv,
            authTag: encryptedData.authTag
        };

        console.log('Sending request to resource server:', formattedRequest);

        const response = await axios.post(
            `${resourceServerBaseUrl}/getAllPosts`, 
            formattedRequest,  // Send formatted request
            {
                headers: { 'Content-Type': 'application/json' },
            }
        );

        if (!response.data.encryptedData) {
            throw new Error('Invalid response format from resource server');
        }

        // Decrypt resource server response
        const decryptedResponse = decryptWithGCM(
            response.data.encryptedData,
            resourceSecret
        );
        
        const posts = JSON.parse(decryptedResponse);
        let postsToSend = Array.isArray(posts) ? posts : [];

        console.log('Posts to send:', postsToSend);

        // Encrypt response for client
        const clientResponse = encryptWithGCM(
            postsToSend,
            Buffer.from(req.session.ecdhParams.aesKey.data)
        );

        return res.json(clientResponse);

    } catch (error) {
        console.error('Error in /bridge/posts:', error);
        const errorResponse = encryptWithGCM(
            { 
                error: error.response?.data?.message || 'Failed to fetch posts',
                status: 'error'
            },
            Buffer.from(req.session.ecdhParams.aesKey.data)
        );
        return res.status(error.response?.status || 500).json(errorResponse);
    }
});

// Fix the post creation endpoint
app.post('/bridge/post', verifySession, verifyECDH, verifyAuth, async(req, res) => {
    try {
        console.log('Post request session:', {
            username: req.session?.resourceServerObj?.username,
            isAuthenticated: req.session?.resourceServerObj?.isAuthenticated,
            groups: req.session?.resourceServerObj?.groups
        });

        if (!req.session?.resourceServerObj?.username) {
            console.error('Username not found in session');
            return res.status(401).json({ error: 'User not properly authenticated' });
        }
        if (!req.session.expectedSequence) {
            req.session.expectedSequence = 0;
        }

        const decrypted = decryptWithGCM(req.body, Buffer.from(req.session.ecdhParams.aesKey.data));
        const message = JSON.parse(decrypted);
        const receivedPost = message.payload;
        console.log('here is the post ' + receivedPost)
        console.log(receivedPost.version)

        // Check sequence number
        if (message.headers.seq !== req.session.expectedSequence) {
            console.error(`Invalid sequence. Expected ${req.session.expectedSequence}, got ${message.headers.seq}`);
            return res.status(400).json({ error: 'Invalid message sequence' });
        }

        console.log('Received post data:', receivedPost);


        const sendPostObj = {
            content: JSON.stringify(receivedPost.content),
            user: req.session.resourceServerObj.username,
            title: JSON.stringify(receivedPost.title),
            isVIP: req.session.resourceServerObj.isVIP || false,
            groupName: req.session.resourceServerObj.groups[0],
            userID: req.session.resourceServerObj.userID,
            sequence: req.session.expectedSequence,
            version: receivedPost.version,
            trueParams: req.session.resourceServerObj.trueParams
        };
        console.log(sendPostObj)
        req.session.expectedSequence++;
        let sendPost = encryptWithGCM(sendPostObj, Buffer.from(global.resourceServerSecret))

        console.log('Sending encrypted post to resource server:', sendPost);

        const encryptedResourceResponse = await axios.post(
            `${resourceServerBaseUrl}/addPost`,
            sendPost,
            {
                headers: {
                    'Content-Type': 'application/json'
                }
            }
        );
        let response = decryptWithGCM(encryptedResourceResponse.data.encryptedData, Buffer.from(global.resourceServerSecret))

        console.log('Resource server response:', response.data);

        // Encrypt the successful response
        const encryptedResponse = encryptWithGCM(
            { success: true, message: 'Post created successfully', data: response.data },
            Buffer.from(req.session.ecdhParams.aesKey.data)
        );

        return res.json(encryptedResponse);

    } catch (error) {
        console.error('Error creating post:', error);
        const errorResponse = {
            success: false,
            message: error.response?.data?.message || 'Failed to create post'
        };
        
        const encryptedError = encryptWithGCM(
            errorResponse,
            Buffer.from(req.session.ecdhParams.aesKey.data)
        );
        
        return res.status(error.response?.status || 500).json(encryptedError);
    }
});

app.delete('/bridge/deletePost', async(req, res) => {
    try {
        const decrypted = JSON.parse(decryptWithGCM(req.body, Buffer.from(req.session.ecdhParams.aesKey.data)));
        
        if (!req.session.resourceServerObj.isAuthenticated || decrypted.username !== req.session.resourceServerObj.username) {
            console.log('Authorization failed:', {
                isAuthenticated: req.session.resourceServerObj.isAuthenticated,
                sessionUsername: req.session.resourceServerObj.username,
                requestUsername: decrypted.username
            });
            return res.status(403).json({ error: 'Not authorized' });
        }

        const deletePostObj = {
            userID: req.session.resourceServerObj.userID,
            postID: decrypted.postID,
            isAdmin: false,
            trueParams: req.session.resourceServerObj.trueParams
        };

        console.log('Delete post request:', deletePostObj);

        let deletePost = encryptWithGCM(deletePostObj, Buffer.from(global.resourceServerSecret))

        try {
            const encryptedResourceResponse = await axios.delete(`${resourceServerBaseUrl}/deletePost`, {
                data: deletePost,
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            let response = decryptWithGCM(encryptedResourceResponse.data.encryptedData, Buffer.from(global.resourceServerSecret))

            console.log('Resource server delete response:', response.data);

            const encryptedResponse = encryptWithGCM(
                { success: true, message: 'Post deleted successfully' },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );

            return res.json(encryptedResponse);

        } catch (error) {
            console.error('Resource server error:', error.response?.data || error.message);
            
            // Handle specific error cases
            if (error.response?.status === 404) {
                const encryptedError = encryptWithGCM(
                    { success: false, message: 'Post not found' },
                    Buffer.from(req.session.ecdhParams.aesKey.data)
                );
                return res.status(404).json(encryptedError);
            }

            const encryptedError = encryptWithGCM(
                { success: false, message: 'Error deleting post' },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );
            return res.status(500).json(encryptedError);
        }
    } catch (error) {
        console.error('Bridge server error:', error);
        const encryptedError = encryptWithGCM(
            { success: false, message: 'Internal server error' },
            Buffer.from(req.session.ecdhParams.aesKey.data)
        );
        return res.status(500).json(encryptedError);
    }
});

//--------------------------login----------------------------------------------------------------------
app.post('/client/params', async(req, res) => {
    try {
        // Check encryption initialization
        if (!req.session?.ecdhParams?.aesKey?.data) {
            console.error('Client encryption not initialized');
            return res.status(500).json({ 
                error: 'Encryption not initialized',
                needsReconnect: true 
            });
        }

        if (!authServerSecret || !authAxiosInstance) {
            console.error('Auth server connection not initialized');
            try {
                await initializeAuthServerEncryption();
            } catch (error) {
                console.error('Failed to initialize auth server connection:', error);
                return res.status(500).json({ 
                    error: 'Failed to initialize auth server connection',
                    needsReconnect: true 
                });
            }
        }

        // Validate and decrypt client request
        const encryptedData = req.body;
        console.log('Received encrypted data from client:', {
            hasEncrypted: !!encryptedData?.encrypted,
            hasIV: !!encryptedData?.iv,
            hasAuthTag: !!encryptedData?.authTag
        });

        if (!encryptedData?.encrypted || !encryptedData?.iv || !encryptedData?.authTag) {
            console.error('Invalid encrypted data format received');
            return res.status(400).json({
                error: 'Invalid request format'
            });
        }

        // Decrypt client request
        let clientCredentials;
        try {
            const decrypted = decryptWithGCM(encryptedData, Buffer.from(req.session.ecdhParams.aesKey.data));
            clientCredentials = JSON.parse(decrypted);

            // Validate decrypted credentials
            if (!clientCredentials.username || !clientCredentials.password) {
                const errorResponse = encryptWithGCM(
                    { 
                        status: 'error',
                        message: 'Username and password are required'
                    },
                    Buffer.from(req.session.ecdhParams.aesKey.data)
                );
                return res.status(400).json(errorResponse);
            }
        } catch (error) {
            console.error('Error decrypting client request:', error);
            return res.status(400).json({
                error: 'Failed to process encrypted data'
            });
        }

        // Encrypt credentials for auth server
        try {
            const encryptedCredentials = encryptWithGCM(clientCredentials, authServerSecret);
            console.log('Encrypted credentials for auth server:', {
                hasEncrypted: !!encryptedCredentials.encrypted,
                hasIV: !!encryptedCredentials.iv,
                hasAuthTag: !!encryptedCredentials.authTag
            });

            // Send to auth server
            const authServerResponse = await authAxiosInstance.post('/verify', encryptedCredentials);
            console.log('Auth server response received');

            if (authServerResponse.data.encryptedData) {
                // Decrypt auth server response
                const decryptedResponse = decryptWithGCM(
                    authServerResponse.data.encryptedData,
                    authServerSecret
                );
                const responseObj = JSON.parse(decryptedResponse);
                

                if (responseObj.isAuthenticated) {
                    // Set session data
                    const sessionData = {
                        isAuthenticated: true,
                        isVIP: responseObj.isVIP || false,
                        isAdmin: responseObj.isAdmin || false,
                        username: clientCredentials.username,
                        groups: responseObj.groups || [],
                        userID: responseObj.userID,
                        trueParams: responseObj,
                        postKeys: responseObj.groupKeys
                        // {
                        //     blue:{
                        //         version 1: '41209234809'
                        //         02: '2308942390'
                        //         03: 'oseruhf9w8'
                        //     },
                        //     red:{
                        //         01: 'sdlkfh47o'
                        //     }
                        // }
                    };

                    req.session.resourceServerObj = sessionData;
                    await new Promise((resolve, reject) => {
                        req.session.save(err => err ? reject(err) : resolve());
                    });

                    console.log('Session data saved:', {
                        username: sessionData.username,
                        isAuthenticated: sessionData.isAuthenticated,
                        groups: sessionData.groups
                    });

                    // Encrypt response for client
                    const clientEncryptedResponse = encryptWithGCM(
                        sessionData,
                        Buffer.from(req.session.ecdhParams.aesKey.data)
                    );

                    return res.json(clientEncryptedResponse);
                }

                // Handle failed authentication
                const failureResponse = encryptWithGCM(
                    {
                        isAuthenticated: false,
                        message: responseObj.message || 'Authentication failed'
                    },
                    Buffer.from(req.session.ecdhParams.aesKey.data)
                );

                return res.json(failureResponse);
            }

            // Handle unexpected auth server response
            throw new Error('Invalid response from auth server');

        } catch (error) {
            console.error('Auth server communication error:', error);
            console.error('Error details:', error.response?.data);

            // Handle auth server session expiry
            if (error.response?.status === 401 && 
                error.response?.data?.message === 'No encryption key established') {
                try {
                    console.log('Attempting to reinitialize auth server connection...');
                    await initializeAuthServerEncryption();
                    return res.redirect(307, '/client/params');
                } catch (reinitError) {
                    console.error('Failed to reinitialize auth connection:', reinitError);
                }
            }

            // Encrypt error response for client
            const errorResponse = encryptWithGCM(
                {
                    isAuthenticated: false,
                    message: error.response?.data?.message || 'Authentication failed'
                },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );
            
            return res.status(error.response?.status || 500).json(errorResponse);
        }

    } catch (error) {
        console.error('Unhandled error in /client/params:', error);
        
        // Send encrypted error if we can, otherwise send plain error
        if (req.session?.ecdhParams?.aesKey?.data) {
            const errorResponse = encryptWithGCM(
                {
                    isAuthenticated: false,
                    message: 'Internal server error'
                },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );
            return res.status(500).json(errorResponse);
        }

        return res.status(500).json({
            error: 'Internal server error',
            needsReconnect: true
        });
    }
});

//global error handler to prevent crashes
process.on('unhandledRejection', (error) => {
    console.error('Unhandled promise rejection:', error);
});

//-------------------------------------------------------------------------------------------------
app.post('/client/register', async (req, res) => {
    try {
        console.log('[Bridge Server] Incoming request to /client/register');

        // Step 1: Validate encryption session
        if (!req.session?.ecdhParams?.aesKey?.data) {
            console.error('[Bridge Server] Encryption session not initialized');
            return res.status(500).json({ error: 'Encryption not initialized', needsReconnect: true });
        }

        const aesKey = Buffer.from(req.session.ecdhParams.aesKey.data);

        // Step 2: Decrypt client request
        const encryptedData = req.body;
        console.log('[Bridge Server] Encrypted registration data received:', encryptedData);

        let decryptedData, userDetails;
        try {
            decryptedData = decryptWithGCM(encryptedData, aesKey);
            userDetails = JSON.parse(decryptedData);
            console.log('[Bridge Server] Decrypted user details:', userDetails);
        } catch (decryptError) {
            console.error('[Bridge Server] Decryption error:', decryptError);
            return res.status(400).json({ error: 'Failed to process encrypted data' });
        }

        // Step 3: Encrypt data for Auth server
        let encryptedUserDetails;
        try {
            encryptedUserDetails = encryptWithGCM(userDetails, authServerSecret);
            console.log('[Bridge Server] Encrypted data for Auth server:', encryptedUserDetails);
        } catch (encryptError) {
            console.error('[Bridge Server] Encryption error:', encryptError);
            return res.status(500).json({ error: 'Failed to encrypt data for Auth server' });
        }

        // Step 4: Send data to Auth server
        try {
            const response = await authAxiosInstance.post('/register', encryptedUserDetails);
            console.log('[Bridge Server] Auth server response received:', response.data);

            // Decrypt Auth server response
            const decryptedAuthResponse = decryptWithGCM(response.data.encryptedData, authServerSecret);
            console.log('[Bridge Server] Decrypted Auth server response:', decryptedAuthResponse);

            // Encrypt response for client
            const clientEncryptedResponse = encryptWithGCM(JSON.parse(decryptedAuthResponse), aesKey);
            return res.status(200).json(clientEncryptedResponse);

        } catch (authError) {
            console.error('[Bridge Server] Auth server error:', authError.response?.data || authError.message);

            // Step 5: Handle missing key by reinitializing
            if (authError.response?.status === 401 && authError.response?.data?.message === 'No encryption key established') {
                console.log('[Bridge Server] Reinitializing encryption session with Auth server...');
                try {
                    await initializeAuthServerEncryption();
                    return res.redirect(307, '/client/register'); // Retry after reinitialization
                } catch (initError) {
                    console.error('[Bridge Server] Failed to reinitialize encryption session:', initError);
                    return res.status(500).json({ error: 'Failed to reinitialize encryption session' });
                }
            }

            // Forward Auth server error
            return res.status(authError.response?.status || 500).json(authError.response?.data || { error: 'Internal server error' });
        }
    } catch (error) {
        console.error('[Bridge Server] Unhandled error in /client/register:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});



// Logout
app.get('/client/logout', async(req, res) => {
    req.session.resourceServerObj = {
        isAuthenticated: false,
        isVIP: false,
        isAdmin: false,
        username: null,
        groups: null,
        userID: null,
        trueParams: {},
        postKeys: null
    };
    console.log('logged out');
    res.send('logged out');
});

app.get('/client/admin', async(req, res) => {
    try {
        if (!req.session.resourceServerObj.isAdmin) {
            return res.status(403).json(encryptWithGCM(
                { error: 'Not authorized' },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            ));
        }

        console.log('Fetching admin user list');
        const adminRequest = encryptWithGCM(
            { isAdmin: req.session.resourceServerObj.isAdmin },
            authServerSecret
        );
        console.log('Admin user list encrypted request log:  ', adminRequest);
        const response = await authAxiosInstance.post(
            `${authServerBaseUrl}/listUsers`,
            adminRequest,
            {
                headers: { 'Content-Type': 'application/json' }
            }
        );

        console.log('Admin user list response: ', response.data);

        if (response.data.encryptedData) {
            const decryptedResponse = decryptWithGCM(
                response.data.encryptedData,
                authServerSecret
            );
            const responseData = JSON.parse(decryptedResponse);
            const clientResponse = encryptWithGCM(
                responseData.data,
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );
            return res.json(clientResponse);
        }

        throw new Error('Invalid response from auth server');
    } catch (error) {
        console.error('Error in /client/admin:', error);
        const errorResponse = encryptWithGCM(
            { error: 'Failed to fetch admin data' },
            Buffer.from(req.session.ecdhParams.aesKey.data)
        );
        return res.status(500).json(errorResponse);
    }
});


app.get('/client/adminGroups', async(req, res) => {
    try {
        if (!req.session.resourceServerObj.isAdmin) {
            return res.status(403).json(encryptWithGCM(
                { error: 'Not authorized' },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            ));
        }

        console.log('Fetching admin group list');
        const adminRequest = encryptWithGCM(
            { isAdmin: req.session.resourceServerObj.isAdmin },
            authServerSecret
        );

        const response = await authAxiosInstance.post(
            `${authServerBaseUrl}/listGroups`,
            adminRequest,
            {
                headers: { 'Content-Type': 'application/json' }
            }
        );

        if (response.data.encryptedData) {
            const decryptedResponse = decryptWithGCM(
                response.data.encryptedData,
                authServerSecret
            );
            const responseData = JSON.parse(decryptedResponse);

            const clientResponse = encryptWithGCM(
                responseData.data,
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );
            return res.json(clientResponse);
        }

        throw new Error('Invalid response from auth server');
    } catch (error) {
        console.error('Error in /client/adminGroups:', error);
        const errorResponse = encryptWithGCM(
            { error: 'Failed to fetch group data' },
            Buffer.from(req.session.ecdhParams.aesKey.data)
        );
        return res.status(500).json(errorResponse);
    }
});


app.post('/client/adminCreate', async(req, res) => {
    try {
        console.log('[Bridge Server] Incoming create user request');
        console.log('[Bridge Server] Session ID:', req.session.id);

        if (!req.session?.ecdhParams?.aesKey?.data) {
            console.error('[Bridge Server] Encryption session not initialized');
            return res.status(500).json(encryptWithGCM(
                { error: 'Encryption not initialized' },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            ));
        }

        if (!req.session.resourceServerObj.isAdmin) {
            console.log('[Bridge Server] Unauthorized create user attempt');
            return res.status(403).json(encryptWithGCM(
                { error: 'Not authorized' },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            ));
        }

        // Decrypt client request
        const decrypted = decryptWithGCM(
            req.body, 
            Buffer.from(req.session.ecdhParams.aesKey.data)
        );
        const createUserObject = JSON.parse(decrypted);
        createUserObject.isAdmin = req.session.resourceServerObj.isAdmin;

        // Encrypt for auth server
        const encryptedRequest = encryptWithGCM(
            createUserObject,
            authServerSecret
        );

        try {
            const response = await authAxiosInstance.post(
                `${authServerBaseUrl}/addUser`,
                encryptedRequest,
                {
                    headers: { 'Content-Type': 'application/json' }
                }
            );


            if (!response.data || !response.data.encryptedData) {
                console.error('[Bridge Server] Invalid response format from auth server');
                throw new Error('Invalid response format from auth server');
            }

            // Handle encrypted response
            const decryptedResponse = decryptWithGCM(
                response.data.encryptedData,
                authServerSecret
            );
            console.log('[Bridge Server] Decrypted response:', decryptedResponse);

            const responseData = JSON.parse(decryptedResponse);
            
            // Encrypt response for client
            const clientResponse = encryptWithGCM(
                responseData,
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );
            return res.json(clientResponse);

        } catch (error) {
            console.error('[Bridge Server] Auth server error:', {
                status: error.response?.status,
                data: error.response?.data
            });

            let errorMessage = 'Failed to create user';
            let statusCode = error.response?.status || 500;

            // Handle encrypted error response
            if (error.response?.data?.encryptedData) {
                try {
                    const decryptedError = decryptWithGCM(
                        error.response.data.encryptedData,
                        authServerSecret
                    );
                    const errorData = JSON.parse(decryptedError);
                    console.log('[Bridge Server] Auth response:', errorData);
                    errorMessage = errorData.message || errorData.error || errorMessage;
                } catch (decryptError) {
                    console.error('[Bridge Server] Failed to decrypt error response:', decryptError);
                }
            }

            // Map status codes to messages
            if (statusCode === 409) {
                errorMessage = 'Username already exists';
            } else if (statusCode === 400) {
                errorMessage = 'Invalid user data provided';
            }

            const clientErrorResponse = encryptWithGCM(
                {
                    status: 'error',
                    message: errorMessage
                },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );

            return res.status(statusCode).json(clientErrorResponse);
        }
    } catch (error) {
        console.error('[Bridge Server] Unexpected error:', error);
        const errorResponse = encryptWithGCM(
            {
                status: 'error',
                message: 'Internal server error'
            },
            Buffer.from(req.session.ecdhParams.aesKey.data)
        );
        return res.status(500).json(errorResponse);
    }
});

app.delete('/client/adminDelete', async (req, res) => {
    try {
        console.log('[Bridge Server] Incoming delete request');
        console.log('[Bridge Server] Session ID:', req.session.id);

        if (!req.session?.ecdhParams?.aesKey?.data) {
            console.error('[Bridge Server] Encryption session not initialized');
            return res.status(500).json(encryptWithGCM(
                { error: 'Encryption not initialized' },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            ));
        }

        // Decrypt client request
        const decrypted = decryptWithGCM(req.body, Buffer.from(req.session.ecdhParams.aesKey.data));
        const deleteDetails = JSON.parse(decrypted);

        const deleteUserName = {
            isAdmin: req.session.resourceServerObj.isAdmin,
            targetUsername: deleteDetails.delUsername,
        };

        // Encrypt request for auth server
        const encryptedRequest = encryptWithGCM(deleteUserName, authServerSecret);
        console.log('[Bridge Server] Request to auth server:', encryptedRequest);

        try {
            const response = await authAxiosInstance.delete('/deleteUser', {
                data: encryptedRequest
            });

            console.log('[Bridge Server] Auth server response:', response.data);

            // Check response format
            if (!response.data || !response.data.encryptedData) {
                console.error('[Bridge Server] Invalid response format from auth server');
                throw new Error('Invalid response format from auth server');
            }

            // Handle encrypted response
            const decryptedResponse = decryptWithGCM(
                response.data.encryptedData,
                authServerSecret
            );
            console.log('[Bridge Server] Decrypted response:', decryptedResponse);

            const responseData = JSON.parse(decryptedResponse);

            // Encrypt response for client
            const clientResponse = encryptWithGCM(
                responseData,
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );

            return res.json(clientResponse);

        } catch (error) {
            console.error('[Bridge Server] Auth server error:');

            let errorMessage = 'Failed to delete user';
            let statusCode = error.response?.status || 500;

            // Try to handle encrypted error response
            if (error.response?.data?.encryptedData) {
                try {
                    const decryptedError = decryptWithGCM(
                        error.response.data.encryptedData,
                        authServerSecret
                    );
                    const errorData = JSON.parse(decryptedError);
                    errorMessage = errorData.message || errorData.error || errorMessage;
                console.log('Auth response:', errorData);
                } catch (decryptError) {
                    console.error('[Bridge Server] Failed to decrypt error response:', decryptError);
                }
            } else if (error.response?.data?.message) {
                errorMessage = error.response.data.message;
            }

            // Create encrypted error response for client
            const clientErrorResponse = encryptWithGCM(
                {
                    status: 'error',
                    message: errorMessage
                },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );

            return res.status(statusCode).json(clientErrorResponse);
        }
    } catch (error) {
        console.error('[Bridge Server] Unexpected error:', error);
        
        const errorResponse = encryptWithGCM(
            {
                status: 'error',
                message: 'Internal server error'
            },
            Buffer.from(req.session.ecdhParams.aesKey.data)
        );
        
        return res.status(500).json(errorResponse);
    }
});

app.delete('/client/adminDeleteGroup', async(req, res) => {
    try {
        console.log('[Bridge Server] Incoming delete group request');
        console.log('[Bridge Server] Session ID:', req.session.id);

        if (!req.session?.ecdhParams?.aesKey?.data) {
            console.error('[Bridge Server] Encryption session not initialized');
            return res.status(500).json(encryptWithGCM(
                { error: 'Encryption not initialized' },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            ));
        }

        if (!req.session.resourceServerObj.isAdmin) {
            console.log('[Bridge Server] Unauthorized delete group attempt');
            return res.status(403).json(encryptWithGCM(
                { error: 'Not authorized' },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            ));
        }

        // Decrypt client request
        const decrypted = decryptWithGCM(req.body, Buffer.from(req.session.ecdhParams.aesKey.data));
        const groupDetails = JSON.parse(decrypted);
        
        let deleteGroupName = {
            isAdmin: req.session.resourceServerObj.isAdmin,
            groupName: groupDetails
        };
        
        
        // Encrypt request for auth server
        const encryptedRequest = encryptWithGCM(deleteGroupName, authServerSecret);
        
        try {
            const response = await authAxiosInstance.delete(`${authServerBaseUrl}/deleteGroup`, {
                data: encryptedRequest,
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            if (!response.data || !response.data.encryptedData) {
                console.error('[Bridge Server] Invalid response format from auth server');
                throw new Error('Invalid response format from auth server');
            }

            // Handle encrypted response
            const decryptedResponse = decryptWithGCM(
                response.data.encryptedData,
                authServerSecret
            );
            console.log('[Bridge Server] Decrypted response:', decryptedResponse);

            const responseData = JSON.parse(decryptedResponse);
            
            // Encrypt response for client
            const clientResponse = encryptWithGCM(
                responseData,
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );
            return res.json(clientResponse);
            
        } catch (error) {
            console.error('[Bridge Server] Auth server error:');
            
            let errorMessage = 'Failed to delete group';
            let statusCode = error.response?.status || 500;

            if (error.response?.data?.encryptedData) {
                try {
                    const decryptedError = decryptWithGCM(
                        error.response.data.encryptedData,
                        authServerSecret
                    );
                    const errorData = JSON.parse(decryptedError);
                    console.log('[Bridge Server] Auth response:', errorData);
                    errorMessage = errorData.message || errorData.error || errorMessage;
                } catch (decryptError) {
                    console.error('[Bridge Server] Failed to decrypt error response:', decryptError);
                }
            }

            const clientErrorResponse = encryptWithGCM(
                {
                    status: 'error',
                    message: errorMessage
                },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );

            return res.status(statusCode).json(clientErrorResponse);
        }
    } catch (error) {
        console.error('[Bridge Server] Unexpected error:', error);
        const errorResponse = encryptWithGCM(
            {
                status: 'error',
                message: 'Internal server error'
            },
            Buffer.from(req.session.ecdhParams.aesKey.data)
        );
        return res.status(500).json(errorResponse);
    }
});

app.post('/client/adminNewGroup', async(req, res) => {
    try {
        console.log('[Bridge Server] Incoming create group request');
        console.log('[Bridge Server] Session ID:', req.session.id);

        if (!req.session?.ecdhParams?.aesKey?.data) {
            console.error('[Bridge Server] Encryption session not initialized');
            return res.status(500).json(encryptWithGCM(
                { error: 'Encryption not initialized' },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            ));
        }

        if (!req.session.resourceServerObj.isAdmin) {
            console.log('[Bridge Server] Unauthorized create group attempt');
            return res.status(403).json(encryptWithGCM(
                { error: 'Not authorized' },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            ));
        }

        // Decrypt client request
        const decrypted = decryptWithGCM(req.body, Buffer.from(req.session.ecdhParams.aesKey.data));
        const groupDetails = JSON.parse(decrypted);
        
        let newGroup = {
            isAdmin: req.session.resourceServerObj.isAdmin,
            groupName: groupDetails
        };
        
        
        // Encrypt request for auth server
        const encryptedRequest = encryptWithGCM(newGroup, authServerSecret);
        
        try {
            const response = await authAxiosInstance.post(
                `${authServerBaseUrl}/createGroup`,
                encryptedRequest,
                {
                    headers: {
                        'Content-Type': 'application/json',
                    }
                }
            );


            if (!response.data || !response.data.encryptedData) {
                console.error('[Bridge Server] Invalid response format from auth server');
                throw new Error('Invalid response format from auth server');
            }

            // Handle encrypted response
            const decryptedResponse = decryptWithGCM(
                response.data.encryptedData,
                authServerSecret
            );
            console.log('[Bridge Server] Decrypted response:', decryptedResponse);

            const responseData = JSON.parse(decryptedResponse);
            
            // Encrypt response for client
            const clientResponse = encryptWithGCM(
                responseData,
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );
            return res.json(clientResponse);
            
        } catch (error) {
            console.error('[Bridge Server] Auth server error:', {
                status: error.response?.status,
                data: error.response?.data
            });
            
            let errorMessage = 'Failed to create group';
            let statusCode = error.response?.status || 500;

            if (error.response?.data?.encryptedData) {
                try {
                    const decryptedError = decryptWithGCM(
                        error.response.data.encryptedData,
                        authServerSecret
                    );
                    const errorData = JSON.parse(decryptedError);
                    console.log('[Bridge Server] Auth response:', errorData);
                    errorMessage = errorData.message || errorData.error || errorMessage;
                } catch (decryptError) {
                    console.error('[Bridge Server] Failed to decrypt error response:', decryptError);
                }
            }

            const clientErrorResponse = encryptWithGCM(
                {
                    status: 'error',
                    message: errorMessage
                },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );

            return res.status(statusCode).json(clientErrorResponse);
        }
    } catch (error) {
        console.error('[Bridge Server] Unexpected error:', error);
        const errorResponse = encryptWithGCM(
            {
                status: 'error',
                message: 'Internal server error'
            },
            Buffer.from(req.session.ecdhParams.aesKey.data)
        );
        return res.status(500).json(errorResponse);
    }
});

app.post('/client/adminAddToGroup', async(req, res) => {
    try {
        console.log('[Bridge Server] Incoming add user to group request');
        console.log('[Bridge Server] Session ID:', req.session.id);

        if (!req.session?.ecdhParams?.aesKey?.data) {
            console.error('[Bridge Server] Encryption session not initialized');
            return res.status(500).json(encryptWithGCM(
                { error: 'Encryption not initialized' },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            ));
        }

        // Decrypt client request
        const decrypted = decryptWithGCM(req.body, Buffer.from(req.session.ecdhParams.aesKey.data));
        const groupData = JSON.parse(decrypted);

        // Prepare request for auth server
        const authServerRequest = {
            isAdmin: req.session.resourceServerObj.isAdmin,
            groupName: groupData.groupAddGroup,
            username: groupData.groupAddUser
        };

        // Encrypt for auth server
        const encryptedRequest = encryptWithGCM(authServerRequest, authServerSecret);

        try {
            const response = await authAxiosInstance.post(
                `${authServerBaseUrl}/addUserToGroup`,
                encryptedRequest,
                {
                    headers: { 'Content-Type': 'application/json' }
                }
            );


            if (!response.data || !response.data.encryptedData) {
                console.error('[Bridge Server] Invalid response format from auth server');
                throw new Error('Invalid response format from auth server');
            }

            // Handle encrypted response
            const decryptedResponse = decryptWithGCM(
                response.data.encryptedData,
                authServerSecret
            );
            console.log('[Bridge Server] Decrypted response:', decryptedResponse);

            const responseData = JSON.parse(decryptedResponse);

            // Encrypt response for client
            const clientResponse = encryptWithGCM(
                responseData,
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );
            return res.json(clientResponse);

        } catch (error) {
            console.error('[Bridge Server] Auth server error:', {
                status: error.response?.status,
                data: error.response?.data
            });

            let errorMessage = 'Failed to add user to group';
            let statusCode = error.response?.status || 500;

            if (error.response?.data?.encryptedData) {
                try {
                    const decryptedError = decryptWithGCM(
                        error.response.data.encryptedData,
                        authServerSecret
                    );
                    const errorData = JSON.parse(decryptedError);
                    console.log('[Bridge Server] Auth response:', errorData);
                    errorMessage = errorData.message || errorData.error || errorMessage;
                } catch (decryptError) {
                    console.error('[Bridge Server] Failed to decrypt error response:', decryptError);
                }
            }

            const clientErrorResponse = encryptWithGCM(
                {
                    status: 'error',
                    message: errorMessage
                },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );

            return res.status(statusCode).json(clientErrorResponse);
        }
    } catch (error) {
        console.error('[Bridge Server] Unexpected error:', error);
        const errorResponse = encryptWithGCM(
            {
                status: 'error',
                message: 'Internal server error'
            },
            Buffer.from(req.session.ecdhParams.aesKey.data)
        );
        return res.status(500).json(errorResponse);
    }
});

app.delete('/client/adminRemoveFromGroup', async(req, res) => {
    try {
        console.log('[Bridge Server] Incoming remove from group request');
        console.log('[Bridge Server] Session ID:', req.session.id);

        if (!req.session?.ecdhParams?.aesKey?.data) {
            console.error('[Bridge Server] Encryption session not initialized');
            return res.status(500).json(encryptWithGCM(
                { error: 'Encryption not initialized' },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            ));
        }

        // Decrypt client request
        const decrypted = decryptWithGCM(req.body, Buffer.from(req.session.ecdhParams.aesKey.data));
        const groupData = JSON.parse(decrypted);

        // Prepare request for auth server
        const authServerRequest = {
            isAdmin: req.session.resourceServerObj.isAdmin,
            username: groupData.groupRemoveUser,
            groupName: groupData.groupRemoveGroup
        };

        // Encrypt for auth server
        const encryptedRequest = encryptWithGCM(authServerRequest, authServerSecret);
        try {
            const response = await authAxiosInstance.delete(
                `${authServerBaseUrl}/removeUserFromGroup`,
                {
                    data: encryptedRequest,
                    headers: { 'Content-Type': 'application/json' }
                }
            );

            if (!response.data || !response.data.encryptedData) {
                console.error('[Bridge Server] Invalid response format from auth server');
                throw new Error('Invalid response format from auth server');
            }

            // Handle encrypted response
            const decryptedResponse = decryptWithGCM(
                response.data.encryptedData,
                authServerSecret
            );
            console.log('[Bridge Server] Decrypted response:', decryptedResponse);

            const responseData = JSON.parse(decryptedResponse);

            // Encrypt response for client
            const clientResponse = encryptWithGCM(
                responseData,
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );
            return res.json(clientResponse);

        } catch (error) {
            console.error('[Bridge Server] Auth server error:', {
                status: error.response?.status,
                data: error.response?.data
            });

            let errorMessage = 'Failed to remove user from group';
            let statusCode = error.response?.status || 500;

            if (error.response?.data?.encryptedData) {
                try {
                    const decryptedError = decryptWithGCM(
                        error.response.data.encryptedData,
                        authServerSecret
                    );
                    const errorData = JSON.parse(decryptedError);
                    console.log('[Bridge Server] Auth response:', errorData);
                    errorMessage = errorData.message || errorData.error || errorMessage;
                } catch (decryptError) {
                    console.error('[Bridge Server] Failed to decrypt error response:', decryptError);
                }
            }

            const clientErrorResponse = encryptWithGCM(
                {
                    status: 'error',
                    message: errorMessage
                },
                Buffer.from(req.session.ecdhParams.aesKey.data)
            );

            return res.status(statusCode).json(clientErrorResponse);
        }
    } catch (error) {
        console.error('[Bridge Server] Unexpected error:', error);
        const errorResponse = encryptWithGCM(
            {
                status: 'error',
                message: 'Internal server error'
            },
            Buffer.from(req.session.ecdhParams.aesKey.data)
        );
        return res.status(500).json(errorResponse);
    }
});

//---------------end of auth server endpoint------------------------------

const startServer = async () => {
    try {
        // Initialize server keys
        await initializeServer();
        console.log('Server keys initialized');
        
        // Initialize resource server auth
        await initializeResourceServerAuth();
        console.log('Resource server auth initialized');
        
        // Initialize auth server encryption
        await initializeAuthServerEncryption();
        console.log('Auth server encryption initialized');

        // Start the server
        const PORT = process.env.PORT || 5064;
        const server = app.listen(PORT, () => {
            console.log(`Server is running on http://localhost:${PORT}`);
        });

        function gracefulShutdown(signal) {
            console.log(`\n${signal} signal received. Starting graceful shutdown.`);
            server.close(() => {
                console.log('HTTP server closed.');
                console.log('Graceful shutdown completed.');
                process.exit(0);
            });
            setTimeout(() => {
                console.error('Could not close connections in time, forcefully shutting down');
                process.exit(1);
            }, 10000);
        }

        // Set up shutdown handlers
        process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
        process.on('SIGINT', () => gracefulShutdown('SIGINT'));
        process.on('uncaughtException', (error) => {
            console.error('Uncaught Exception:', error);
            gracefulShutdown('uncaughtException');
        });

        process.on('unhandledRejection', (reason, promise) => {
            console.error('Unhandled Rejection at:', promise, 'reason:', reason);
            gracefulShutdown('unhandledRejection');
        });

    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
};

// Start the server
startServer();