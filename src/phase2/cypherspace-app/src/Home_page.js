import React, { useState, useEffect, useContext, version } from 'react';
import { CryptoContext } from './App';
import './Home_page.css';
import { Buffer } from 'buffer'

const API_BASE_URL = 'http://localhost:5064';

const HomePage = ({ username, onSignOut, isVIP, groups, keys }) => {
    const crypto = useContext(CryptoContext);
    const [showPostForm, setShowPostForm] = useState(false);
    const [postTitle, setPostTitle] = useState("");
    const [postContent, setPostContent] = useState("");
    const [posts, setPosts] = useState([]); 
    const [isSubmitted, setIsSubmitted] = useState(false);
    const [error, setError] = useState(null);
    const [isDeleting, setIsDeleting] = useState(false);
    const [messageSequence, setMessageSequence] = useState(0);

    const getDisplayName = () => {
        if (!username || username === 'undefined') return 'Hello Guest!';
        if (isVIP) return `Hello ${username} (VIP)!`;
        return `Hello ${username}!`;
    };

    const displayName = getDisplayName();
    
useEffect(() => {
    const fetchPosts = async () => {
        try {
            // Determine the fetch URL based on the username
            const fetchUrl = (username === 'Guest')
                ? `${API_BASE_URL}/bridge/guest`
                : `${API_BASE_URL}/bridge/posts`;

            console.log('Fetching posts for user:', username);

            // Fetch posts from the server
            const response = await fetch(fetchUrl, {
                method: 'GET',
                credentials: 'include',
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            console.log('Received data:', data);

            if (username === 'Guest') {
                // Handle raw guest data
                if (Array.isArray(data)) {
                    setPosts(data); // Set posts directly for guest users
                    setError(null);
                } else {
                    throw new Error('Invalid data format for guest posts');
                }
            } else {
                // Handle encrypted data for authenticated users
                if (!data.encrypted || !data.iv || !data.authTag) {
                    throw new Error('Invalid encrypted data format');
                }
                const decryptedData = await crypto.decrypt(data);
                console.log('Decrypted posts:', decryptedData);
                console.log('KEYS TO BE USED:', keys)
                if (Array.isArray(decryptedData)) {
                    const decryptedPosts = await Promise.all(decryptedData.map(async post => {
                        try{
                            const groupKeys = keys[groups?.[0]]
                            const rawKey = Buffer.from(groupKeys[post.version], 'base64');
                            const versionKey = await window.crypto.subtle.importKey(
                                "raw",
                                rawKey,
                                { name: "AES-GCM" },
                                false,
                                ["decrypt"]
                            );
                            if (!versionKey) {
                                console.error('No key for version:', post.version);
                                return post;
                            }
                            console.log(JSON.parse(post.title))
                            let title = JSON.parse(post.title)
                            console.log(Object.values(title.encrypted))
                            const parsableTitle = new Uint8Array(Object.values(title.encrypted))
                            const parsableTitleAuthtag = new Uint8Array(Object.values(title.authTag))
                            const parsableTitleIv = new Uint8Array(Object.values(title.iv))

                            //I might have to call window.importkey
                            const combined1 = new Uint8Array([...parsableTitle, ...parsableTitleAuthtag])
                            const decrypted1 = await window.crypto.subtle.decrypt(
                                {
                                    name: "AES-GCM",
                                    iv: parsableTitleIv
                                },
                                versionKey,
                                combined1
                            )
                            const decryptedTitle = (new TextDecoder().decode(decrypted1))
                            console.log('title '+ decryptedTitle)
                            const content = JSON.parse(post.content)
                            const parsableContent = new Uint8Array(Object.values(content.encrypted))
                            const parsableContentAuthtag = new Uint8Array(Object.values(content.authTag))
                            const parsableContentIv = new Uint8Array(Object.values(content.iv))



                            const combined2 = new Uint8Array([...parsableContent, ...parsableContentAuthtag])
                            const decrypted2 = await window.crypto.subtle.decrypt(
                                {
                                    name: "AES-GCM",
                                    iv: parsableContentIv
                                },
                                versionKey,
                                combined2
                            )
                            const decryptedContent = (new TextDecoder().decode(decrypted2))
                            return {
                                ...post,
                                title: decryptedTitle,
                                content: decryptedContent
                            }
                        }
                        catch(error){
                            console.error('Error decrypting post:', error);
                            return post;
                        }

                    }))
                    
                    setPosts(decryptedPosts); // Set decrypted posts for authenticated users
                    setError(null);
                } else {
                    throw new Error('Decrypted data is not an array');
                }
            }
        } catch (error) {
            console.error('Error fetching posts:', error);
            setError(error.message);
            setPosts([]); // Clear posts on error
        }
    };

    fetchPosts();
}, [username, isSubmitted, crypto, showPostForm]);



    const handlePostSubmit = async (e) => {
    e.preventDefault();
    try {
        if (!username || username === 'undefined') {
            setError('Must be logged in to post');
            return;
        }

        if (!postTitle.trim() || !postContent.trim()) {
            setError('Title and content are required');
            return;
        }
        //encrypt title
        const iv1 = window.crypto.getRandomValues(new Uint8Array(16));
        const groupKeys = keys[groups?.[0]]
        const latestVersion = Math.max(...Object.keys(groupKeys).map(Number));
        const currentKey = groupKeys[latestVersion]
        const rawKey = Buffer.from(currentKey, 'base64');
        const encryptionKey = await window.crypto.subtle.importKey(
            "raw",
            rawKey,
            { name: "AES-GCM" },
            false,
            ["encrypt"]
        );
        const encoded1 = new TextEncoder().encode(postTitle.trim());
        const encryptedTitle = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv:iv1 },
            encryptionKey,
            encoded1
        );
        const encryptedTitleArray = new Uint8Array(encryptedTitle);
        const titleAuthTag = encryptedTitleArray.slice(-16);
        const titleCiphertext = encryptedTitleArray.slice(0, -16);

        //encrypt post
        const iv2 = window.crypto.getRandomValues(new Uint8Array(16));
        const encoded2 = new TextEncoder().encode(postContent.trim());
        const encryptedContent = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv:iv2 },
            encryptionKey,
            encoded2
        );

        const encryptedContentArray = new Uint8Array(encryptedContent);
        const contentAuthTag = encryptedContentArray.slice(-16);
        const contentCiphertext = encryptedContentArray.slice(0, -16);


        const newPost = {
            headers:{
                seq:messageSequence
            },
            payload:{
                title: {
                    encrypted: titleCiphertext,
                    iv: iv1,
                    authTag: titleAuthTag
                },
                content: {
                    encrypted: contentCiphertext,
                    iv: iv2,
                    authTag: contentAuthTag
                },
                user: username,
                userType: isVIP ? 'VIP' : 'normal',
                groupName: groups?.[0] || 'guest',
                version: latestVersion
            }
        };

        console.log('Sending post data:', newPost);

        const encryptedPost = await crypto.encrypt(newPost);
        console.log('Encrypted post data:', encryptedPost);

        const response = await fetch(`${API_BASE_URL}/bridge/post`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify(encryptedPost),
        });

        // Increment sequence after successful send
        setMessageSequence(prev => prev + 1);

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Failed to create post');
        }

        const encryptedResponse = await response.json();
        const decryptedResponse = await crypto.decrypt(encryptedResponse);
        console.log('Post creation response:', decryptedResponse);

        if (decryptedResponse.success === false) {
            throw new Error(decryptedResponse.message || 'Failed to create post');
        }

        setShowPostForm(false);
        setPostTitle("");
        setPostContent("");
        setIsSubmitted(true);
        setError(null);
    } catch (error) {
        console.error('Error creating post:', error);
        setError(error.message || 'Failed to create post');
    }
};

 const handleDelete = async (e, postID) => {
        e.preventDefault();
        if (isDeleting) return; // Prevent double deletion

        try {
            setIsDeleting(true);
            setError(null);

            const delObject = {
                username,
                postID
            };

            console.log('Sending delete request for post:', postID);

            const encryptedDelObject = await crypto.encrypt(delObject);

            const response = await fetch(`${API_BASE_URL}/bridge/deletePost`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include',
                body: JSON.stringify(encryptedDelObject)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to delete post');
            }

            const encryptedResponse = await response.json();
            const decryptedResponse = await crypto.decrypt(encryptedResponse);

            console.log('Delete response:', decryptedResponse);

            if (decryptedResponse.success) {
                // Remove the deleted post from the local state
                setPosts(prevPosts => prevPosts.filter(post => post.postID !== postID));
                setIsSubmitted(true);
            } else {
                throw new Error(decryptedResponse.message || 'Failed to delete post');
            }

        } catch (error) {
            console.error('Error deleting post:', error);
            setError(error.message || 'Failed to delete post');
        } finally {
            setIsDeleting(false);
        }
    };

    const handleCancel = () => {
        setShowPostForm(false);
        setPostTitle("");
        setPostContent("");
    };

    return (
        <div className="home-page-container">
            <div className="home-header">
                <span className="cypherspace-title">CypherSpace</span>
                <h1 className="home-title">HOME</h1>
                <div className="user-info">
                    <span className="username-display">{displayName}</span>
                    {username && username !== 'undefined' && username !== "Guest" && (
                        <button className="post-btn" onClick={() => setShowPostForm(true)}>
                            Post
                        </button>
                    )}
                    <button className="sign-out-btn" onClick={onSignOut}>Sign Out</button>
                </div>
            </div>

            {error && (
                <div className="error-message">
                    {error}
                </div>
            )}

            {showPostForm && (
                <div className="post-modal">
                    <div className="post-form">
                        <h2>Create a Post</h2>
                        <form onSubmit={handlePostSubmit}>
                            <input
                                type="text"
                                placeholder="Title"
                                value={postTitle}
                                onChange={(e) => setPostTitle(e.target.value)}
                                required
                            />
                            <textarea
                                placeholder="Content"
                                value={postContent}
                                onChange={(e) => setPostContent(e.target.value)}
                                required
                            ></textarea>
                            <div className="form-actions">
                                <button type="submit" className="send-btn">Send</button>
                                <button type="button" className="cancel-btn" onClick={handleCancel}>Cancel</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            <div className="posts-container">
                {posts.length > 0 ? (
                    posts.map((post, index) => (
                        <div key={index} className="post-item">
                            <h2>{post.title}</h2>
                            <p>{post.content}</p>
                            <p>
                                <strong>Posted by:</strong> {post.user} 
                                ({post.vip ? 'VIP User' : 'Normal User'})
                            </p>
                            {post.user === username && username !== 'undefined' && (
                                <button 
                                    type="button" 
                                    className="delete-btn"
                                    onClick={(e) => handleDelete(e, post.postID)}
                                >
                                    Delete
                                </button>
                            )}
                        </div>
                    ))
                ) : (
                    <p className="no-posts-message">Start participating!</p>
                )}
            </div>
        </div>
    );
};

export default HomePage;