# CS1653-Group-Project
**Contributors: @rucNick, @Alex-Acero-Security, @Xingcheng03, @DylanKaing**

# CypherSpace

A secure, encrypted social networking platform built with React frontend and Spring Boot backend services, featuring comprehensive security measures including end-to-end encryption, server identity verification, and role-based access control.

## 🔐 Security Features

- **End-to-End Encryption**: All communications encrypted using AES-256-GCM
- **Server Identity Verification**: RSA-based server authentication with fingerprint verification
- **ECDH Key Exchange**: Secure key establishment for client-server communication
- **Group-Based Encryption**: Dynamic key rotation for secure group messaging
- **Request Sequence Protection**: Prevention of replay attacks
- **Role-Based Access Control**: Admin, VIP, and regular user permissions

## 🏗️ Architecture

The system follows a three-tier architecture:

1. **Frontend (React)**: User interface with client-side encryption
2. **Bridge Server (Node.js)**: Middleware handling encryption/decryption and authentication
3. **Backend Services**:
   - **Authentication Server (Spring Boot)**: User management and authentication
   - **Resource Server (Spring Boot)**: Post management and data storage

## 📋 Prerequisites

- **Node.js** (v16 or higher)
- **Java** (v17 or higher) 
- **Maven** (v3.6 or higher)
- **SQLite** (included with servers)

## 🚀 Installation & Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd cypherspace-app
```

### 2. Setup Frontend (React)

```bash
cd src/phase2/cypherspace-app
npm install
```

### 3. Setup Bridge Server (Node.js)

```bash
cd src/phase2/cypherspace-app/server/bridge
npm install
```

### 4. Setup Authentication Server (Spring Boot)

```bash
cd src/phase2/cypherspace-app/server/spring
mvn clean install
```

### 5. Setup Resource Server (Spring Boot)

```bash
cd src/phase2/cypherspace-app/server/resourceServer
mvn clean install
```

## 🏃‍♂️ Running the Application

### Start All Services (Recommended Order)

1. **Authentication Server**
```bash
cd src/phase2/cypherspace-app/server/spring
mvn spring-boot:run
# Runs on http://localhost:8064
```

2. **Resource Server**
```bash
cd src/phase2/cypherspace-app/server/resourceServer  
mvn spring-boot:run
# Runs on http://localhost:4064
```

3. **Bridge Server**
```bash
cd src/phase2/cypherspace-app/server/bridge
npm start
# Runs on http://localhost:5064
```

4. **Frontend**
```bash
cd src/phase2/cypherspace-app
npm start
# Runs on http://localhost:3000
```

## 🌐 Service Endpoints

### Frontend (Port 3000)
- Main application interface
- Handles user interactions and client-side encryption

### Bridge Server (Port 5064)
- `/server-identity` - Server identity verification
- `/verify-identity` - ECDH key exchange
- `/bridge/guest` - Guest post access
- `/bridge/posts` - Authenticated post access
- `/bridge/post` - Create new post
- `/client/params` - User authentication
- `/client/register` - User registration
- `/client/admin*` - Admin operations

### Authentication Server (Port 8064)
- `/verify` - User credential verification
- `/register` - User registration
- `/listUsers` - Admin user management
- `/listGroups` - Admin group management
- `/initiate-key-exchange` - ECDH initialization
- `/complete-key-exchange` - ECDH completion

### Resource Server (Port 4064)
- `/addPost` - Create posts
- `/getAllPosts` - Retrieve posts
- `/deletePost` - Delete posts
- `/getGuestPosts` - Public posts for guests

## 👥 User Roles & Features

### 🎭 Guest Users
- View public posts in the "guest" group
- No authentication required
- Read-only access

### 👤 Regular Users  
- Create and view posts in assigned groups
- Delete own posts
- Group-based content access
- End-to-end encrypted communications

### 💎 VIP Users
- All regular user features
- Access to VIP-only content
- Special user designation
- Enhanced privileges

### 🛡️ Administrator Users
- Full system administration
- User management (create, delete, modify)
- Group management (create, delete, assign users)
- Access to admin dashboard
- System monitoring capabilities

## 🔑 Security Implementation

### Client-Server Communication
1. **Server Verification**: RSA signature verification with stored fingerprints
2. **Key Exchange**: ECDH-based shared secret establishment  
3. **Encryption**: AES-256-GCM for all communications
4. **Authentication**: Signed tokens with user credentials

### Group Security
- **Dynamic Key Rotation**: Keys updated when users join/leave groups
- **Version Management**: Multiple key versions for backward compatibility
- **Access Control**: Group membership determines content visibility

### Attack Prevention
- **Replay Protection**: Sequence numbers prevent message replay
- **MITM Protection**: Server fingerprint verification
- **Data Integrity**: GCM authentication tags
- **Session Security**: Secure session management

## 📝 Usage Examples

### User Registration
1. Navigate to the application
2. Click "Create new account"
3. Fill in username, password, and optional VIP code
4. Submit registration form

### Creating Posts
1. Log in with credentials
2. Click "Post" button
3. Enter title and content
4. Posts are automatically encrypted before transmission

### Admin Operations
1. Log in with admin credentials
2. Access admin dashboard automatically
3. Manage users and groups through dedicated forms

## 🗄️ Database Schema

### Users Table
- `id` (Primary Key)
- `username` (Unique)
- `password_hash`
- `is_vip`
- `admin`

### Groups Table  
- `id` (Primary Key)
- `group_name` (Unique)

### Posts Table
- `post_id` (Primary Key)
- `title` (Encrypted)
- `content` (Encrypted)
- `user`
- `is_vip`
- `group_name`
- `user_id`
- `version`

### Group Keys Table
- `id` (Primary Key)
- `group_id` (Foreign Key)
- `key_value`
- `version`

## 🔧 Configuration

### Key Files
- RSA key pairs generated automatically on first startup
- ECDH keys generated per session
- Group encryption keys managed dynamically

## 🛠️ Development

### Project Structure
```
cypherspace-app/
├── src/                          # React frontend
├── server/
│   ├── bridge/                   # Node.js bridge server
│   ├── spring/                   # Authentication server
│   └── resourceServer/           # Resource/data server
├── public/                       # Static assets
└── README.md
```

### Technology Stack
- **Frontend**: React, Web Crypto API, CSS3
- **Bridge Server**: Node.js, Express, Crypto
- **Backend**: Spring Boot, JPA/Hibernate, SQLite
- **Security**: RSA, ECDH, AES-GCM, HKDF


## ⚠️ Security Notes

- This is a demonstration system
- Conduct thorough security audits before production use
- Keep all dependencies updated
- Monitor for security vulnerabilities
- Implement additional security measures as needed for production environments
