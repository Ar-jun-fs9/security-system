const express = require('express');
const router = express.Router();
const argon2 = require('argon2');
const db = require('../config/db');
const { sendVerificationEmail, encryptToken } = require('../config/email');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { authenticateToken, verifyToken } = require('../config/auth');
const jwt = require('jsonwebtoken');

// Function to convert IPv6 ::1 to IPv4 127.0.0.1
const formatIpAddress = (ip) => {
    if (ip === '::1' || ip === '::ffff:127.0.0.1') {
        return '127.0.0.1';
    }
    return ip;
};

// Decryption function
const decryptToken = (encryptedToken) => {
    try {
        if (!process.env.ENCRYPTION_KEY) {
            throw new Error('ENCRYPTION_KEY is not set in environment variables');
        }

        // Ensure the key is exactly 32 bytes
        const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
        if (ENCRYPTION_KEY.length !== 32) {
            throw new Error('ENCRYPTION_KEY must be 32 bytes (64 hex characters)');
        }

        const textParts = encryptedToken.split(':');
        const iv = Buffer.from(textParts[0], 'hex');
        const encryptedText = Buffer.from(textParts[1], 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (error) {
        console.error('Token decryption error:', error);
        return null;
    }
};

// Register
router.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        console.log('Registration attempt for:', { username, email });

        // Add audit logging context
        req.auditContext = {
            actionType: 'USER_REGISTRATION',
            actionCategory: 'AUTHENTICATION',
            actionDetails: { username, email }
        };

        // Check if username or email already exists
        const existingUser = await db.query(
            'SELECT * FROM user_register WHERE username = $1 OR email = $2',
            [username, email]
        );

        if (existingUser.rows.length > 0) {
            if (existingUser.rows[0].username === username) {
                // Log failed registration attempt
                await db.query(
                    `INSERT INTO audit_log (
                        actor_username,
                        actor_type,
                        action,
                        target_username,
                        target_email,
                        description,
                        ip_address,
                        user_agent,
                        metadata
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
                    [
                        username,
                        'user',
                        'registration',
                        `${username}\n${email}`,
                        email,
                        'Registration failed - username already exists',
                        req.headers['x-forwarded-for'] || req.socket.remoteAddress,
                        req.headers['user-agent'],
                        JSON.stringify({ reason: 'username_exists' })
                    ]
                );
                return res.status(400).json({ error: 'Username already exists' });
            }
            if (existingUser.rows[0].email === email) {
                // Log failed registration attempt
                await db.query(
                    `INSERT INTO audit_log (
                        actor_username,
                        actor_type,
                        action,
                        target_username,
                        target_email,
                        description,
                        ip_address,
                        user_agent,
                        metadata
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
                    [
                        username,
                        'user',
                        'registration',
                        `${username}\n${email}`,
                        email,
                        'Registration failed - email already exists',
                        req.headers['x-forwarded-for'] || req.socket.remoteAddress,
                        req.headers['user-agent'],
                        JSON.stringify({ reason: 'email_exists' })
                    ]
                );
                return res.status(400).json({ error: 'Email already exists' });
            }
        }

        const passwordHash = await argon2.hash(password);
        const registerMethod = 'local';
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const passwordExpiry = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000); // 90 days from now
        console.log('Generated verification token:', verificationToken);

        // Begin transaction
        await db.query('BEGIN');

        try {
            // Insert user registration
            const result = await db.query(
                `INSERT INTO user_register 
                (username, email, password_hash, register_method, verification_token, email_verified, password_expiry) 
                VALUES ($1, $2, $3, $4, $5, $6, $7) 
                RETURNING id`,
                [username, email, passwordHash, registerMethod, verificationToken, false, passwordExpiry]
            );

            const userId = result.rows[0].id;
            console.log('User registered with ID:', userId);

            // Send verification email
            const emailSent = await sendVerificationEmail(email, username, verificationToken);
            if (!emailSent) {
                // Log failed email sending
                await db.query(
                    `INSERT INTO audit_log (
                        actor_username,
                        actor_type,
                        action,
                        target_username,
                        target_email,
                        description,
                        ip_address,
                        user_agent,
                        metadata
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
                    [
                        username,
                        'user',
                        'registration',
                        `${username}\n${email}`,
                        email,
                        'Registration failed - verification email not sent',
                        req.headers['x-forwarded-for'] || req.socket.remoteAddress,
                        req.headers['user-agent'],
                        JSON.stringify({ userId, reason: 'email_send_failed' })
                    ]
                );
                // If email sending fails, rollback transaction
                await db.query('ROLLBACK');
                return res.status(500).json({ error: 'Failed to send verification email' });
            }

            // Log registration attempt (pending verification)
            // await db.query(
            //     `INSERT INTO audit_log (
            //         actor_username,
            //         actor_type,
            //         action,
            //         target_username,
            //         target_email,
            //         description,
            //         ip_address,
            //         user_agent,
            //         metadata
            //     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
            //     [
            //         username, // actor_username (e.g., currently logged-in user, or 'system')
            //         'user',   // actor_type
            //         'registration',
            //         `${username}\n${email}`,
            //         email,  // ✅ target_email
            //         'Registration attempt - email verification pending',
            //         req.headers['x-forwarded-for'] || req.socket.remoteAddress,
            //         req.headers['user-agent'],
            //         JSON.stringify({
            //             userId,
            //             registerMethod,
            //             verificationStatus: 'pending'
            //         })
            //     ]
            // );


            // Commit transaction
            await db.query('COMMIT');

            res.json({
                message: 'Registration successful. Please check your email to verify your account.',
                requiresVerification: true
            });
        } catch (error) {
            // Log registration error
            await db.query(
                `INSERT INTO audit_log (
                    actor_username,
                    actor_type,
                    action,
                    target_username,
                    target_email,
                    description,
                    ip_address,
                    user_agent,
                    metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
                [
                    username,
                    'user',
                    'registration',
                    `${username}\n${email}`,
                    email,
                    'Registration failed - database error',
                    req.headers['x-forwarded-for'] || req.socket.remoteAddress,
                    req.headers['user-agent'],
                    JSON.stringify({ error: error.message })
                ]
            );
            // Rollback transaction on error
            await db.query('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Verify Email
router.get('/verify-email', async (req, res) => {
    try {
        const { token } = req.query;
        console.log('Received verification token:', token);

        if (!token) {
            return res.status(400).json({ error: 'Verification token is required' });
        }

        // Decrypt the token
        const decryptedToken = decryptToken(token);
        console.log('Decrypted token:', decryptedToken);

        if (!decryptedToken) {
            console.log('Token decryption failed');
            return res.status(400).json({ error: 'Invalid verification token' });
        }

        // First, let's check if the token exists in the database
        const tokenCheck = await db.query(
            'SELECT id, username, email, email_verified, verification_token FROM user_register WHERE verification_token = $1 OR (email_verified = true AND verification_token = $1)',
            [decryptedToken]
        );
        console.log('Token check result:', tokenCheck.rows);

        if (tokenCheck.rows.length === 0) {
            console.log('No user found with this verification token');
            return res.status(400).json({ error: 'Invalid or expired verification token' });
        }

        const user = tokenCheck.rows[0];
        if (user.email_verified) {
            console.log('Email already verified for user:', user.id);
            return res.json({ message: 'Email already verified. You can now login.' });
        }

        // Update the user's verification status but keep the token
        const result = await db.query(
            'UPDATE user_register SET email_verified = true WHERE id = $1 RETURNING id, email, verification_token',
            [user.id]
        );
        console.log('Update result:', result.rows);

        if (result.rows.length === 0) {
            console.log('Failed to update user verification status');
            return res.status(400).json({ error: 'Failed to verify email' });
        }

        // Log successful email verification
        // await db.query(
        //     `INSERT INTO audit_log (
        //         actor_username,
        //         actor_type,
        //         action,
        //         target_username,
        //         target_email,
        //         description,
        //         ip_address,
        //         user_agent,
        //         metadata
        //     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        //     [
        //         user.username,
        //         'user',
        //         'registration',
        //         `${user.username}\n${user.email}`,
        //         user.email,
        //         'Registration successful - email verified',
        //         req.headers['x-forwarded-for'] || req.socket.remoteAddress,
        //         req.headers['user-agent'],
        //         JSON.stringify({ userId: user.id, verificationStatus: 'completed' })
        //     ]
        // );

        res.json({ message: 'Email verified successfully' });
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({ error: 'Email verification failed' });
    }
});

// Login
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log('Login attempt for username:', username);

        const loginMethod = 'local';
        const loginDate = new Date();
        const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const userAgent = req.headers['user-agent'];

        // Check login attempts first
        const loginAttemptsResult = await db.query(
            'SELECT * FROM login_attempts WHERE username = $1',
            [username]
        );

        let loginAttempts = loginAttemptsResult.rows[0];

        // If user is blocked, check if block has expired
        if (loginAttempts && loginAttempts.is_blocked) {
            if (loginAttempts.block_expires_at && loginAttempts.block_expires_at > new Date()) {
                // Log failed login attempt
                await db.query(
                    `INSERT INTO audit_log (
                        actor_username,
                        actor_type,
                        action,
                        description,
                        ip_address,
                        user_agent,
                        metadata
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                    [
                        username,
                        'user',
                        'login',
                        'Login attempt blocked - account is locked',
                        ipAddress,
                        userAgent,
                        JSON.stringify({ isBlocked: true, blockExpiresAt: loginAttempts.block_expires_at })
                    ]
                );
                return res.status(403).json({
                    error: 'Your account is blocked. Please contact your administrator.',
                    isBlocked: true
                });
            } else {
                // Reset block if expired
                await db.query(
                    'UPDATE login_attempts SET is_blocked = false, attempt_count = 0, block_expires_at = NULL WHERE username = $1',
                    [username]
                );
                loginAttempts.is_blocked = false;
                loginAttempts.attempt_count = 0;
            }
        }

        // Get user from database
        const userResult = await db.query(
            'SELECT * FROM user_register WHERE username = $1',
            [username]
        );

        if (userResult.rows.length === 0) {
            // Log failed login attempt - user not found
            await db.query(
                `INSERT INTO audit_log (
                    actor_username,
                    actor_type,
                    action,
                    description,
                    ip_address,
                    user_agent,
                    metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [
                    username,
                    'user',
                    'login',
                    'Login failed - user not found',
                    ipAddress,
                    userAgent,
                    JSON.stringify({ status: 'failed', reason: 'user_not_found' })
                ]
            );
            console.log('Login failed: User not found');
            return res.status(404).json({ error: 'User not found' });
        }

        const user = userResult.rows[0];
        console.log('User found with ID:', user.id);

        // Check if email is verified
        if (!user.email_verified) {
            // Log failed login attempt - email not verified
            await db.query(
                `INSERT INTO audit_log (
                    actor_id,
                    actor_username,
                    actor_type,
                    action,
                    description,
                    ip_address,
                    user_agent,
                    metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                [
                    user.id,
                    username,
                    'user',
                    'login',
                    'Login failed - email not verified',
                    ipAddress,
                    userAgent,
                    JSON.stringify({ status: 'failed', reason: 'email_not_verified' })
                ]
            );
            return res.status(401).json({
                error: 'Please verify your email first',
                email_verified: false,
                email: user.email
            });
        }

        // Verify password
        const validPassword = await argon2.verify(user.password_hash, password);
        if (!validPassword) {
            // Log failed login attempt - invalid password
            await db.query(
                `INSERT INTO audit_log (
                    actor_id,
                    actor_username,
                    actor_type,
                    action,
                    description,
                    ip_address,
                    user_agent,
                    metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                [
                    user.id,
                    username,
                    'user',
                    'login',
                    'Login failed - invalid password',
                    ipAddress,
                    userAgent,
                    JSON.stringify({ status: 'failed', reason: 'invalid_password' })
                ]
            );

            // Update or create login attempts record
            if (!loginAttempts) {
                await db.query(
                    'INSERT INTO login_attempts (user_id, username, attempt_count) VALUES ($1, $2, 1)',
                    [user.id, username]
                );
                loginAttempts = { attempt_count: 1 };
            } else {
                await db.query(
                    'UPDATE login_attempts SET attempt_count = attempt_count + 1, last_attempt = CURRENT_TIMESTAMP WHERE username = $1',
                    [username]
                );
                loginAttempts.attempt_count += 1;
            }

            const remainingAttempts = 3 - loginAttempts.attempt_count;

            // Block account if 3 failed attempts
            if (loginAttempts.attempt_count >= 3) {
                await db.query(
                    'UPDATE login_attempts SET is_blocked = true, block_expires_at = CURRENT_TIMESTAMP + INTERVAL \'1 hour\' WHERE username = $1',
                    [username]
                );
                return res.status(403).json({
                    error: 'Your account is blocked for 1 hour. Please try again later.',
                    isBlocked: true,
                    blockExpiresIn: '1 hour'
                });
            }

            console.log('Login failed: Invalid password');
            return res.status(401).json({
                error: 'Invalid password',
                remainingAttempts: remainingAttempts,
                message: `You have ${remainingAttempts} attempt${remainingAttempts !== 1 ? 's' : ''} left before your account is blocked.`
            });
        }

        // Reset login attempts on successful login
        if (loginAttempts) {
            await db.query(
                'UPDATE login_attempts SET attempt_count = 0, is_blocked = false, block_expires_at = NULL WHERE username = $1',
                [username]
            );
        }

        // Update or insert login record
        const loginResult = await db.query(
            'SELECT * FROM user_login WHERE user_id = $1',
            [user.id]
        );

        if (loginResult.rows.length === 0) {
            // First login
            await db.query(
                'INSERT INTO user_login (user_id, username, email, password_hash, login_method, login_date, login_count, ip_address, user_agent) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
                [user.id, username, user.email, user.password_hash, loginMethod, loginDate, 1, ipAddress, userAgent]
            );
            console.log('First login record created for user:', user.id);
        } else {
            // Update existing login record
            await db.query(
                'UPDATE user_login SET login_date = $1, login_count = login_count + 1, ip_address = $2, user_agent = $3 WHERE user_id = $4',
                [loginDate, ipAddress, userAgent, user.id]
            );
            console.log('Login record updated for user:', user.id);
        }

        // Log successful login
        await db.query(
            `INSERT INTO audit_log (
                actor_id,
                actor_username,
                actor_type,
                action,
                description,
                ip_address,
                user_agent,
                metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [
                user.id,
                username,
                'user',
                'login',
                'Successful login',
                ipAddress,
                userAgent,
                JSON.stringify({
                    status: 'success',
                    loginMethod,
                    loginCount: loginResult.rows.length > 0 ? loginResult.rows[0].login_count + 1 : 1
                })
            ]
        );

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            email_verified: true,
            token
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Resend Verification Email
router.post('/resend-verification', async (req, res) => {
    try {
        const { email } = req.body;

        // Get user from database
        const userResult = await db.query(
            'SELECT * FROM user_register WHERE email = $1',
            [email]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = userResult.rows[0];

        if (user.email_verified) {
            return res.status(400).json({ error: 'Email already verified' });
        }

        // Generate new verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');

        // Update verification token in database
        await db.query(
            'UPDATE user_register SET verification_token = $1 WHERE email = $2',
            [verificationToken, email]
        );

        // Send new verification email
        const emailSent = await sendVerificationEmail(email, user.username, verificationToken);
        if (!emailSent) {
            return res.status(500).json({ error: 'Failed to send verification email' });
        }

        res.json({ message: 'Verification email sent successfully' });
    } catch (error) {
        console.error('Resend verification error:', error);
        res.status(500).json({ error: 'Failed to resend verification email' });
    }
});

// Forgot Password - Verify Email
router.post('/forgot-password/verify', async (req, res) => {
    try {
        const { email } = req.body;

        const userResult = await db.query(
            'SELECT id, username, email FROM user_register WHERE email = $1',
            [email]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'Email not found' });
        }

        const user = userResult.rows[0];
        res.json({
            message: 'Email verified',
            user: {
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({ error: 'Verification failed' });
    }
});

// Forgot Password - Change Password
router.post('/forgot-password/change', async (req, res) => {
    try {
        const { email, newPassword } = req.body;
        const passwordChangeDate = new Date();

        // Get user
        const userResult = await db.query(
            'SELECT * FROM user_register WHERE email = $1',
            [email]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = userResult.rows[0];
        const newPasswordHash = await argon2.hash(newPassword);

        // Check against current password
        if (await argon2.verify(user.password_hash, newPassword)) {
            return res.status(400).json({
                error: 'This password has been used recently. Please choose a different password.'
            });
        }

        // Check password history
        const historyResult = await db.query(
            'SELECT password_hash FROM password_history WHERE user_id = $1 ORDER BY changed_at DESC LIMIT 5',
            [user.id]
        );

        // Check if new password matches any of the last 5 passwords
        for (const record of historyResult.rows) {
            if (await argon2.verify(record.password_hash, newPassword)) {
                return res.status(400).json({
                    error: 'This password has been used recently. Please choose a different password.'
                });
            }
        }

        // Format IP address
        const ipAddress = req.ip === '::1' ? '127.0.0.1' : req.ip;

        // Begin transaction
        await db.query('BEGIN');

        try {
            // Update password in user_register
            await db.query(
                'UPDATE user_register SET password_hash = $1, password_expiry = $2 WHERE email = $3',
                [newPasswordHash, new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), email]
            );

            // Update password in user_login
            await db.query(
                'UPDATE user_login SET password_hash = $1 WHERE user_id = $2',
                [newPasswordHash, user.id]
            );

            // Prepare metadata
            const metadata = {
                change_method: 'forgot_password',
                change_time: passwordChangeDate.toISOString(),
                ip_address: ipAddress,
                user_agent: req.headers['user-agent'] || 'Unknown'
            };

            // Insert into password history with metadata
            await db.query(
                'INSERT INTO password_history (user_id, password_hash, changed_by, metadata) VALUES ($1, $2, $3, $4)',
                [
                    user.id,
                    newPasswordHash,
                    'user',
                    JSON.stringify(metadata)
                ]
            );

            // Generate new reset token and expiry
            const resetToken = jwt.sign(
                { id: user.id, email: user.email },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );
            const tokenExpiry = new Date(Date.now() + 3600000); // 1 hour from now

            // Update or insert forgot_password record
            const forgotResult = await db.query(
                'SELECT * FROM forgot_password WHERE user_id = $1',
                [user.id]
            );

            if (forgotResult.rows.length === 0) {
                // First password change
                await db.query(
                    'INSERT INTO forgot_password (user_id, email, reset_token, token_expiry, password_change_date, password_change_count) VALUES ($1, $2, $3, $4, $5, $6)',
                    [user.id, email, resetToken, tokenExpiry, passwordChangeDate, 1]
                );
            } else {
                // Update existing record
                await db.query(
                    'UPDATE forgot_password SET reset_token = $1, token_expiry = $2, password_change_date = $3, password_change_count = password_change_count + 1 WHERE user_id = $4',
                    [resetToken, tokenExpiry, passwordChangeDate, user.id]
                );
            }

            // Commit transaction
            await db.query('COMMIT');

            res.json({ message: 'Password changed successfully' });
        } catch (error) {
            // Rollback transaction on error
            await db.query('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Generate OTP
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send OTP Email
const sendOTPEmail = async (email, otp) => {
    try {
        const transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 587,
            secure: false,
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_APP_PASSWORD
            },
            tls: {
                rejectUnauthorized: false
            }
        });

        const mailOptions = {
            from: {
                name: 'Security System',
                address: process.env.GMAIL_USER
            },
            to: email,
            subject: 'Password Reset OTP',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Password Reset OTP</title>
                </head>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background-color: #ffffff; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <div style="text-align: center; margin-bottom: 30px;">
                            <h2 style="color: #2c3e50; margin-bottom: 10px;">Password Reset OTP</h2>
                            <p style="font-size: 16px; color: #666;">Your OTP for password reset is:</p>
                        </div>
                        
                        <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; text-align: center;">
                            <h1 style="color: #3498db; font-size: 32px; letter-spacing: 5px; margin: 0;">${otp}</h1>
                            <p style="color: #666; margin-top: 10px;">This OTP will expire in 1 minute.</p>
                        </div>

                        <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
                            <p style="color: #666; margin: 5px 0;">If you didn't request this OTP, please ignore this email.</p>
                            <p style="color: #2c3e50; font-weight: bold; margin: 5px 0;">The Security System Team</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('OTP email sent successfully:', info.messageId);
        return true;
    } catch (error) {
        console.error('Error sending OTP email:', error);
        return false;
    }
};

// Send OTP
router.post('/send-otp', async (req, res) => {
    const client = await db.pool.connect();
    try {
        const { email } = req.body;
        console.log('Attempting to send OTP to:', email);

        // Check if user exists
        const userResult = await client.query(
            'SELECT * FROM user_register WHERE email = $1',
            [email]
        );

        if (userResult.rows.length === 0) {
            console.log('No user found with email:', email);
            return res.status(404).json({ error: 'User not found' });
        }

        const user = userResult.rows[0];
        console.log('User found:', user.username);

        // Generate OTP
        const otp = generateOTP();
        const otpExpiry = new Date(Date.now() + 60000); // 1 minute expiry
        console.log('Generated OTP:', otp, 'Expiry:', otpExpiry);

        // Start transaction
        await client.query('BEGIN');

        try {
            // Store OTP in database
            const insertResult = await client.query(
                'INSERT INTO otp_verification (user_id, email, otp, expiry) VALUES ($1, $2, $3, $4) ON CONFLICT (email) DO UPDATE SET user_id = $1, otp = $3, expiry = $4 RETURNING *',
                [user.id, email, otp, otpExpiry]
            );

            if (!insertResult.rows || insertResult.rows.length === 0) {
                throw new Error('Failed to store OTP');
            }

            console.log('OTP successfully stored in database:', {
                email: insertResult.rows[0].email,
                expiry: insertResult.rows[0].expiry
            });

            // Verify the insertion
            const verifyInsert = await client.query(
                'SELECT * FROM otp_verification WHERE email = $1',
                [email]
            );

            if (!verifyInsert.rows || verifyInsert.rows.length === 0) {
                throw new Error('OTP storage verification failed');
            }

            console.log('OTP storage verified:', verifyInsert.rows[0]);

            // Send OTP email
            const emailSent = await sendOTPEmail(email, otp);
            if (!emailSent) {
                throw new Error('Failed to send OTP email');
            }

            // Commit transaction
            await client.query('COMMIT');
            console.log('OTP email sent successfully to:', email);

            res.json({
                message: 'OTP sent successfully',
                user: {
                    username: user.username,
                    email: user.email
                }
            });
        } catch (error) {
            // Rollback transaction on error
            await client.query('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Send OTP error:', error);
        res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
    } finally {
        client.release();
    }
});

// Verify OTP
router.post('/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;

        // Get OTP from database
        const otpResult = await db.query(
            'SELECT * FROM otp_verification WHERE email = $1 AND otp = $2 AND expiry > NOW()',
            [email, otp]
        );

        if (otpResult.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        // Delete used OTP
        // await db.query(
        //     'DELETE FROM otp_verification WHERE email = $1',
        //     [email]
        // );

        res.json({ message: 'OTP verified successfully' });
    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({ error: 'Failed to verify OTP' });
    }
});

// Change Password
router.post('/change-password', async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        // Get user and check password expiry
        const userResult = await db.query(
            'SELECT id, password_expiry FROM user_register WHERE email = $1',
            [email]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = userResult.rows[0];
        const now = new Date();
        const passwordExpiry = new Date(user.password_expiry);

        // Check if password is expired
        if (passwordExpiry && now > passwordExpiry) {
            return res.status(403).json({
                error: 'Password has expired. Please change your password.',
                requiresPasswordChange: true
            });
        }

        // Hash new password
        const passwordHash = await argon2.hash(newPassword);

        // Update password in database
        await db.query(
            'UPDATE user_register SET password_hash = $1 WHERE email = $2',
            [passwordHash, email]
        );

        // Update password in login table
        await db.query(
            'UPDATE user_login SET password_hash = $1 WHERE email = $2',
            [passwordHash, email]
        );

        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Change password error:', error);
        if (error.message.includes('Password has been used recently')) {
            return res.status(400).json({ error: error.message });
        }
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// Get User Profile
router.get('/profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        // Get user data from database
        const userResult = await db.query(
            'SELECT id, username, email, register_method, email_verified, created_at FROM user_register WHERE id = $1',
            [userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = userResult.rows[0];

        // Get login history with IP and device info
        const loginResult = await db.query(
            'SELECT login_date, login_count, ip_address, user_agent FROM user_login WHERE user_id = $1',
            [userId]
        );

        const userData = {
            ...user,
            login_history: loginResult.rows[0] || null
        };

        res.json(userData);
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get user profile update eligibility
router.get('/profile/update-eligibility', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;

        // Check if user can update profile (2 months cooldown)
        const eligibilityQuery = `
            SELECT 
                next_update_allowed,
                CASE 
                    WHEN next_update_allowed IS NULL OR next_update_allowed <= CURRENT_TIMESTAMP 
                    THEN true 
                    ELSE false 
                END as can_update
            FROM (
                SELECT next_update_allowed 
                FROM profile_update_history 
                WHERE user_id = $1 
                ORDER BY updated_at DESC 
                LIMIT 1
            ) latest_update
        `;

        const eligibilityResult = await db.query(eligibilityQuery, [userId]);
        const canUpdate = eligibilityResult.rows.length === 0 || eligibilityResult.rows[0]?.can_update || false;
        const nextUpdateAllowed = eligibilityResult.rows[0]?.next_update_allowed || new Date();

        res.json({
            canUpdate,
            nextUpdateAllowed: nextUpdateAllowed.toISOString(),
            message: canUpdate ? 'Profile can be updated' : 'Profile update not allowed yet'
        });
    } catch (error) {
        console.error('Error checking profile update eligibility:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update user profile
router.put('/profile/update', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { username, email } = req.body;

        // Validate input
        if (!username || !email) {
            return res.status(400).json({ error: 'Username and email are required' });
        }

        // Check if user can update profile (2 months cooldown)
        const eligibilityQuery = `
            SELECT 
                COALESCE(MAX(next_update_allowed), CURRENT_TIMESTAMP) as next_update_allowed,
                CASE 
                    WHEN COALESCE(MAX(next_update_allowed), CURRENT_TIMESTAMP) <= CURRENT_TIMESTAMP 
                    THEN true 
                    ELSE false 
                END as can_update
            FROM profile_update_history 
            WHERE user_id = $1
        `;

        const eligibilityResult = await db.query(eligibilityQuery, [userId]);
        const canUpdate = eligibilityResult.rows[0]?.can_update || true;

        if (!canUpdate) {
            return res.status(403).json({
                error: 'Profile update not allowed yet. Please wait until the cooldown period expires.'
            });
        }

        // Check if username or email already exists
        const existingUserQuery = `
            SELECT id, username, email 
            FROM user_register 
            WHERE (username = $1 OR email = $2) AND id != $3
        `;
        const existingUserResult = await db.query(existingUserQuery, [username, email, userId]);

        if (existingUserResult.rows.length > 0) {
            const existingUser = existingUserResult.rows[0];
            if (existingUser.username === username) {
                return res.status(400).json({ error: 'Username already exists' });
            }
            if (existingUser.email === email) {
                return res.status(400).json({ error: 'Email already exists' });
            }
        }

        // Get current user data
        const currentUserQuery = 'SELECT username, email FROM user_register WHERE id = $1';
        const currentUserResult = await db.query(currentUserQuery, [userId]);

        if (currentUserResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const currentUser = currentUserResult.rows[0];

        // Begin transaction
        await db.query('BEGIN');

        try {
            // Update user profile
            const updateQuery = `
                UPDATE user_register 
                SET username = $1, email = $2
                WHERE id = $3
            `;
            await db.query(updateQuery, [username, email, userId]);

            // Record profile update history with formatted IP address
            const historyQuery = `
                INSERT INTO profile_update_history 
                (user_id, old_username, new_username, old_email, new_email, ip_address, user_agent)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
            `;
            await db.query(historyQuery, [
                userId,
                currentUser.username,
                username,
                currentUser.email,
                email,
                formatIpAddress(req.ip),
                req.headers['user-agent']
            ]);

            // Commit transaction
            await db.query('COMMIT');

            res.json({
                message: 'Profile updated successfully',
                user: {
                    id: userId,
                    username,
                    email
                }
            });
        } catch (error) {
            // Rollback transaction on error
            await db.query('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get blocked users (admin only)
router.get('/blocked-users', authenticateToken, async (req, res) => {
    try {
        // Check if user is admin
        const adminCheck = await db.query(
            'SELECT id FROM admin_users WHERE id = $1',
            [req.user.id]
        );

        if (!adminCheck.rows[0]) {
            return res.status(403).json({ error: 'Unauthorized access' });
        }

        const blockedUsers = await db.query(
            'SELECT username, last_attempt, block_expires_at FROM login_attempts WHERE is_blocked = true AND block_expires_at > CURRENT_TIMESTAMP'
        );

        res.json({ blockedUsers: blockedUsers.rows });
    } catch (error) {
        console.error('Error fetching blocked users:', error);
        res.status(500).json({ error: 'Failed to fetch blocked users' });
    }
});

// Unblock user (admin only)
router.post('/unblock-user', authenticateToken, async (req, res) => {
    try {
        const { username } = req.body;

        // Check if user is admin
        const adminCheck = await db.query(
            'SELECT id FROM admin_users WHERE id = $1',
            [req.user.id]
        );

        if (!adminCheck.rows[0]) {
            return res.status(403).json({ error: 'Unauthorized access' });
        }

        // Delete the login attempts record for the user
        await db.query(
            'DELETE FROM login_attempts WHERE username = $1',
            [username]
        );

        res.json({ message: 'User unblocked successfully' });
    } catch (error) {
        console.error('Error unblocking user:', error);
        res.status(500).json({ error: 'Failed to unblock user' });
    }
});

module.exports = router; 