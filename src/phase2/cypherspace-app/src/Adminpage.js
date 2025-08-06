import React, { useEffect, useState, useContext } from "react";
import './Adminpage.css';  // Include the CSS file
import Login from "./Login";
import { CryptoContext } from './App';  // Import CryptoContext

const Adminpage = () => {
    const crypto = useContext(CryptoContext);
    const [users, setUsers] = useState([]);
    const [groups, setGroups] = useState([])
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [isVIP, setIsVIP] = useState(false);
    const [delUsername, setDelUsername] = useState('')
    const [newGroup, setNewGroup] = useState('')
    const [delGroup, setDelgroup] = useState('')
    const [groupAddUser, setGroupAddUser] = useState('')
    const [groupAddGroup, setGroupAddGroup] = useState('')
    const [groupRemoveUser, setGroupRemoveUser] = useState('')
    const [groupRemoveGroup, setGroupRemoveGroup] = useState('')
    const [isSubmitted, setIsSubmitted] = useState(false)
    const [isSignedOut, setIsSignedOut] = useState(false)

    useEffect(() => {
        const fetchUsers = async () => {
            try {
                setTimeout(async () => {
                    const response = await fetch('http://localhost:5064/client/admin', {
                        method: 'GET',
                        credentials: 'include'
                    });
                    const encryptedData = await response.json();
                    const decryptedUsers = await crypto.decrypt(encryptedData);
                    setUsers(decryptedUsers);
                    setIsSubmitted(false);
                }, 1000);
            } catch (error) {
                console.error(error);
            }
        };
        fetchUsers();
    }, [isSubmitted, crypto]);

    useEffect(() => {
        const fetchGroups = async () => {
            try {
                setTimeout(async () => {
                    const response = await fetch('http://localhost:5064/client/adminGroups', {
                        method: 'GET',
                        credentials: 'include'
                    });
                    const encryptedData = await response.json();
                    const decryptedGroups = await crypto.decrypt(encryptedData);
                    setGroups(decryptedGroups);
                }, 1000);
            } catch (error) {
                console.error(error);
            }
        };
        fetchGroups();
    }, [isSubmitted, crypto]);

    const handleCreateUser = async (e) => {
        e.preventDefault();


        try {
            const newUser = { username: username, password: password, isVIP: isVIP };
            const encryptedUser = await crypto.encrypt(newUser);
            const response = await fetch('http://localhost:5064/client/adminCreate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify(encryptedUser),
            });
            const encryptedResponse = await response.json();
            const decryptedResponse = await crypto.decrypt(encryptedResponse);
            setUsers([...users, decryptedResponse]);
        } catch (error) {
            console.error('Error creating user:', error);
        }
        setUsername('');
        setPassword('');
        setIsVIP(false);
        setIsSubmitted(true);
    };
    const handleDeleteUser = async (e) => {
    e.preventDefault();
    const userDel = { delUsername };

    try {
        // Encrypt the request
        const encryptedData = await crypto.encrypt(userDel);

        // Send the request to the Bridge Server
        const response = await fetch('http://localhost:5064/client/adminDelete', {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify(encryptedData),
        });

        if (!response.ok) {
            throw new Error('Failed to delete user');
        }

        console.log('User deleted successfully');
    } catch (error) {
        console.error('Error deleting user:', error);
    } finally {
        setDelUsername('');
        setIsSubmitted(true);
    }
};

    const handleDeleteGroup = async (e) => {
        e.preventDefault();
        try {
            const encryptedGroup = await crypto.encrypt(delGroup);
            await fetch('http://localhost:5064/client/adminDeleteGroup', {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include',
                body: JSON.stringify(encryptedGroup)
            });
        } catch (error) {
            console.error(error);
        }
        setDelgroup('');
        setIsSubmitted(true);
    };
    const handleNewGroup = async (e) => {
        e.preventDefault();
        try {
            const encryptedGroup = await crypto.encrypt(newGroup);
            await fetch('http://localhost:5064/client/adminNewGroup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include',
                body: JSON.stringify(encryptedGroup)
            });
        } catch (error) {
            console.error(error);
        }
        setIsSubmitted(true);
        setNewGroup('');
    };
    const handleAddUserGroup = async (e) => {
        e.preventDefault();
        const addInfo = { groupAddUser, groupAddGroup };

        try {
            const encryptedInfo = await crypto.encrypt(addInfo);
            await fetch('http://localhost:5064/client/adminAddToGroup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify(encryptedInfo),
            });
        } catch (error) {
            console.error('Error adding to group:', error);
        }
        setGroupAddUser('');
        setGroupAddGroup('');
        setIsSubmitted(true);
    };
    const handleDeleteUserGroup = async (e) => {
        e.preventDefault();
        const delInfo = { groupRemoveUser, groupRemoveGroup };

        try {
            const encryptedInfo = await crypto.encrypt(delInfo);
            await fetch('http://localhost:5064/client/adminRemoveFromGroup', {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify(encryptedInfo),
            });
        } catch (error) {
            console.error('Error removing from group:', error);
        }
        setGroupRemoveUser('');
        setGroupRemoveGroup('');
        setIsSubmitted(true);
    };

    const handleSignOut = async () => {
        setIsSignedOut(true);
        try {
            const response = await fetch('http://localhost:5064/client/logout', {
                method: 'GET',
                credentials: 'include'
            });
            if (response.ok) {
                console.log('Signed out');
            }
        } catch (error) {
            console.error('Error during request:', error);
        }
    };

    if (isSignedOut) {
        return <Login />
    }


    return (
        <div id="wrapper">
            <div className="admin-header">
                <h1 className="home-title">ADMINISTRATOR</h1> {/* Title at the center */}
                <div className="user-info">
                    <button className="sign-out-btn" onClick={handleSignOut}>Sign Out</button> {/* Sign Out button */}
                </div>
            </div>
            <div className="admin-container">
                <div id='lists'>
                    <div>
                        <h1 className="pixel-font">User List</h1>
                        <table className="user-table">
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Admin</th>
                                    <th>VIP</th>
                                    <th>GROUPS</th>
                                </tr>
                            </thead>
                            <tbody>
                                {users.map((user, index) => (
                                    <tr key={index} className={user.isAdmin ? 'admin-row' : ''}>
                                        <td>{user.username}</td>
                                        <td>{user.isAdmin ? 'Yes' : 'No'}</td>
                                        <td>{user.isVIP ? 'Yes' : 'No'}</td>
                                        <td>{user.groups && user.groups.length > 0 ? user.groups.join(', ') : 'No groups'}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    <div>
                        <h1 className="pixel-font" id="group-list-title">Group List</h1>
                        <table className="group-table">
                            <thead>
                                <tr>
                                    <th>Group Name</th>
                                    <th>Users</th>
                                </tr>
                            </thead>
                            <tbody>
                                {Object.keys(groups).map((groupName, index) => (
                                    <tr key={index}>
                                        <td>{groupName}</td>
                                        <td>
                                            {groups[groupName].length > 0
                                                ? groups[groupName].map(user => user.username).join(', ')
                                                : 'No users'}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
                <div className="forms-container">
                    {/* Form for creating a new user */}
                    <div>
                        <h1 className="pixel-font">Create New User</h1>
                        <form onSubmit={handleCreateUser} className="create-user-form">
                            <div className="form-group">
                                <label htmlFor="username">Username</label>
                                <input
                                    type="text"
                                    id="username"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label htmlFor="password">Password</label>
                                <input
                                    type="password"
                                    id="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label htmlFor="isVIP">Is VIP</label>
                                <input
                                    type="checkbox"
                                    id="isVIP"
                                    checked={isVIP}
                                    onChange={(e) => setIsVIP(e.target.checked)}
                                />
                            </div>
                            <button type="submit">Create User</button>
                        </form>
                    </div>
                    {/* Form User deletion */}
                    <div>
                        <h1 className="pixel-font">Delete User</h1>
                        <form onSubmit={handleDeleteUser} className="create-user-form">
                            <div className="form-group">
                                <label htmlFor="username">Username</label>
                                <input
                                    type="text"
                                    id="delUsername"
                                    value={delUsername}
                                    onChange={(e) => setDelUsername(e.target.value)}
                                    required
                                />
                            </div>
                            <button className="deleteBtn">Delete User</button>
                        </form>
                    </div>
                    {/* Form Add Group */}
                    <div>
                        <h1 className="pixel-font">Add New Group</h1>
                        <form onSubmit={handleNewGroup} className="create-user-form">
                            <div className="form-group">
                                <label htmlFor="newGroup">Group name</label>
                                <input
                                    type="text"
                                    id="newGroup"
                                    value={newGroup}
                                    onChange={(e) => setNewGroup(e.target.value)}
                                    required
                                />
                            </div>
                            <button type="submit">Create group</button>
                        </form>
                    </div>
                    {/* Form Delete Group */}
                    <div id="del2">
                        <h1 className="pixel-font">Delete Group</h1>
                        <form onSubmit={handleDeleteGroup} className="create-user-form">
                            <div className="form-group">
                                <label htmlFor="newGroup">Group name</label>
                                <input
                                    type="text"
                                    id="newGroup2"
                                    value={delGroup}
                                    onChange={(e) => setDelgroup(e.target.value)}
                                    required
                                />
                            </div>
                            <button className="deleteBtn">Delete group</button>
                        </form>
                    </div>
                    {/* Form Add User To Group */}
                    <div id="addUserToGroupForm">
                        <h1 className="pixel-font">Add User To Group</h1>
                        <form onSubmit={handleAddUserGroup} className="create-user-form">
                            <div className="form-group">
                                <label htmlFor="username">Username</label>
                                <input
                                    type="text"
                                    id="username2"
                                    value={groupAddUser}
                                    onChange={(e) => setGroupAddUser(e.target.value)}
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label htmlFor="newGroup">Group name</label>
                                <input
                                    type="text"
                                    id="newGroup3"
                                    value={groupAddGroup}
                                    onChange={(e) => setGroupAddGroup(e.target.value)}
                                    required
                                />
                            </div>
                            <button type="submit">Add User</button>
                        </form>
                    </div>
                    {/* Form Remove User From Group */}
                    <div id="RemoveUserFrom">
                        <h1 className="pixel-font">Remove User From Group</h1>
                        <form onSubmit={handleDeleteUserGroup} className="create-user-form">
                            <div className="form-group">
                                <label htmlFor="username5">Username</label>
                                <input
                                    type="text"
                                    id="username5"
                                    value={groupRemoveUser}
                                    onChange={(e) => setGroupRemoveUser(e.target.value)}
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label htmlFor="newGroup">Group name</label>
                                <input
                                    type="text"
                                    id="Group3"
                                    value={groupRemoveGroup}
                                    onChange={(e) => setGroupRemoveGroup(e.target.value)}
                                    required
                                />
                            </div>
                            <button className="deleteBtn">Remove User</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Adminpage;