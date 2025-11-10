const express = require('express');
const router = express.Router();
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('../config/db');
const { transporter } = require('../config/email');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { verifyAdminToken } = require('../middleware/auth');

// Helper function to format IP address
const formatIpAddress = (ip) => {
    if (!ip) return null;
    // Handle IPv6 localhost
    if (ip === '::1' || ip === '::ffff:127.0.0.1') {
        return '127.0.0.1';
    }
    // Handle IPv4-mapped IPv6 addresses
    if (ip.startsWith('::ffff:')) {
        return ip.substring(7);
    }
    return ip;
};

// Admin Login
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // Format IP address
        const ipAddress = req.ip === '::1' ? '127.0.0.1' : req.ip;

        // First check admin_users table
        let adminResult = await db.query(
            'SELECT * FROM admin_users WHERE username = $1',
            [username]
        );

        let admin = null;
        let isFromUserRegister = false;

        if (adminResult.rows.length > 0) {
            // Found in admin_users table
            admin = adminResult.rows[0];
            const validPassword = await argon2.verify(admin.password_hash, password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid password' });
            }
        } else {
            // Check user_register table for admin role
            const userResult = await db.query(
                'SELECT * FROM user_register WHERE username = $1 AND role = $2',
                [username, 'admin']
            );

            if (userResult.rows.length > 0) {
                admin = userResult.rows[0];
                isFromUserRegister = true;
                const validPassword = await argon2.verify(admin.password_hash, password);
                if (!validPassword) {
                    return res.status(401).json({ error: 'Invalid Password' });
                }
            } else {
                return res.status(401).json({ error: 'Username not exist' });
            }
        }

        // Update login information
        if (isFromUserRegister) {
            // For user_register table, update user_login and log the login in audit_log
            // Update user_login record if exists, else insert
            const loginUpdateResult = await db.query(
                `UPDATE user_login 
                 SET login_date = CURRENT_TIMESTAMP, 
                     login_count = COALESCE(login_count, 0) + 1, 
                     ip_address = $1, 
                     user_agent = $2 
                 WHERE user_id = $3 
                 RETURNING user_id`,
                [ipAddress, req.headers['user-agent'], admin.id]
            );
            if (loginUpdateResult.rowCount === 0) {
                // No record exists, insert new
                await db.query(
                    `INSERT INTO user_login 
                    (user_id, username, email, password_hash, login_method, login_count, login_date, ip_address, user_agent) 
                    VALUES ($1, $2, $3, $4, $5, 1, CURRENT_TIMESTAMP, $6, $7)`,
                    [
                        admin.id,
                        admin.username,
                        admin.email,
                        admin.password_hash,
                        admin.register_method || 'local',
                        ipAddress,
                        req.headers['user-agent']
                    ]
                );
            }
            await db.query(
                `INSERT INTO audit_log (
                    actor_id,
                    actor_type,
                    actor_username,
                    target_email,
                    target_username,
                    action,
                    description,
                    ip_address,
                    user_agent,
                    metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
                [
                    admin.id,
                    'admin',
                    admin.username,
                    admin.email,
                    admin.username,
                    'admin_login',
                    'Admin login via changed role',
                    ipAddress,
                    req.headers['user-agent'],
                    JSON.stringify({ source: 'user_register' })
                ]
            );
        } else {
            // For admin_users table, update all login information
            await db.query(
                `UPDATE admin_users 
                SET last_login = CURRENT_TIMESTAMP,
                    login_count = COALESCE(login_count, 0) + 1,
                    ip_address = $1,
                    user_agent = $2
                WHERE id = $3`,
                [ipAddress, req.headers['user-agent'], admin.id]
            );
        }

        // Generate JWT token
        const token = jwt.sign(
            {
                id: admin.id,
                username: admin.username,
                email: admin.email,
                role: admin.role,
                isFromUserRegister
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            admin: {
                id: admin.id,
                username: admin.username,
                email: admin.email,
                role: admin.role,
                isFromUserRegister
            }
        });
    } catch (error) {
        console.error('Error in admin login:', error);
        res.status(500).json({ error: 'Failed to login' });
    }
});

// Get Admin Profile
router.get('/profile', verifyAdminToken, async (req, res) => {
    try {
        const adminId = req.admin.id;
        const isFromUserRegister = req.admin.isFromUserRegister;

        let admin;
        if (isFromUserRegister) {
            // Get admin info from user_register table
            const result = await db.query(
                'SELECT id, username, email, role, created_at FROM user_register WHERE id = $1',
                [adminId]
            );
            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'Admin not found' });
            }
            admin = result.rows[0];
        } else {
            // Get admin info from admin_users table
            const result = await db.query(
                'SELECT id, username, email, role, created_at, last_login, login_count FROM admin_users WHERE id = $1',
                [adminId]
            );
            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'Admin not found' });
            }
            admin = result.rows[0];
        }

        res.json({
            admin: {
                id: admin.id,
                username: admin.username,
                email: admin.email,
                role: admin.role,
                created_at: admin.created_at,
                last_login: admin.last_login,
                login_count: admin.login_count,
                isFromUserRegister
            }
        });
    } catch (error) {
        console.error('Error fetching admin profile:', error);
        res.status(500).json({ error: 'Failed to fetch admin profile' });
    }
});

// Get Admin Login History
router.get('/login-history', verifyAdminToken, async (req, res) => {
    try {
        const query = `
            SELECT 
                last_login as login_time,
                ip_address,
                user_agent,
                login_count
            FROM admin_users 
            WHERE id = $1
            ORDER BY last_login DESC
        `;
        const result = await db.query(query, [req.admin.id]);

        res.json({
            loginHistory: result.rows
        });
    } catch (error) {
        console.error('Login history fetch error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin Send OTP
router.post('/send-otp', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

    try {
        console.log('Attempting to send OTP to:', email);

        // Check if admin exists
        const query = 'SELECT * FROM admin_users WHERE email = $1';
        const result = await db.query(query, [email]);

        if (result.rows.length === 0) {
            console.log('No admin found with email:', email);
            return res.status(404).json({ error: 'No admin account found with this email' });
        }

        const admin = result.rows[0];
        console.log('Admin found:', admin.username);

        // Generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 10 * 60000); // 10 minutes from now

        console.log('Generated OTP for admin:', admin.username);

        // Store OTP in database
        const updateQuery = `
            UPDATE admin_users 
            SET otp = $1, 
                otp_expiry = $2 
            WHERE id = $3
        `;
        await db.query(updateQuery, [otp, otpExpiry, admin.id]);
        console.log('OTP stored in database');

        // Verify email configuration
        if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
            console.error('Email configuration missing');
            throw new Error('Email configuration is not properly set up');
        }

        // Send OTP email
        const mailOptions = {
            from: {
                name: 'Security System',
                address: process.env.GMAIL_USER
            },
            to: email,
            subject: 'Admin Password Reset OTP',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Admin Password Reset OTP</title>
                </head>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background-color: #ffffff; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <h2 style="color: #2c3e50; margin-bottom: 20px;">Password Reset OTP</h2>
                        <p>Hello ${admin.username},</p>
                        <p>Your OTP for password reset is:</p>
                        <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
                            <h1 style="color: #2c3e50; margin: 0; letter-spacing: 5px;">${otp}</h1>
                        </div>
                        <p><strong>Note:</strong> This OTP will expire in 10 minutes.</p>
                        <p>If you didn't request this, please ignore this email and ensure your account is secure.</p>
                        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
                            <p style="color: #666;">Best regards,<br>Security System Team</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        console.log('Attempting to send email...');
        await transporter.sendMail(mailOptions);
        console.log('Email sent successfully');

        res.json({
            message: 'OTP has been sent to your email',
            user: {
                id: admin.id,
                username: admin.username,
                email: admin.email
            }
        });
    } catch (error) {
        console.error('Send OTP error:', error);
        // Send more specific error message
        if (error.message.includes('Email configuration')) {
            res.status(500).json({ error: 'Email service is not properly configured. Please contact the administrator.' });
        } else {
            res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
        }
    }
});

// Admin Verify OTP
router.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;

    try {
        // Find admin with valid OTP
        const query = `
            SELECT * FROM admin_users 
            WHERE email = $1 
            AND otp = $2 
            AND otp_expiry > NOW()
        `;
        const result = await db.query(query, [email, otp]);

        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        const admin = result.rows[0];

        // Generate temporary token for password reset
        const resetToken = jwt.sign(
            { id: admin.id, email: admin.email },
            process.env.JWT_SECRET,
            { expiresIn: '15m' }
        );

        res.json({
            message: 'OTP verified successfully',
            resetToken,
            user: {
                id: admin.id,
                username: admin.username,
                email: admin.email
            }
        });
    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({ error: 'Failed to verify OTP. Please try again.' });
    }
});

// Admin Reset Password
router.post('/reset-password', async (req, res) => {
    const { resetToken, newPassword } = req.body;

    if (!resetToken || !newPassword) {
        return res.status(400).json({ error: 'Reset token and new password are required' });
    }

    try {
        // Verify reset token
        const decoded = jwt.verify(resetToken, process.env.JWT_SECRET);

        // Find admin
        const query = 'SELECT * FROM admin_users WHERE id = $1 AND email = $2';
        const result = await db.query(query, [decoded.id, decoded.email]);

        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid reset token' });
        }

        const admin = result.rows[0];

        // Hash new password
        const hashedPassword = await argon2.hash(newPassword);

        // Update password and clear OTP
        const updateQuery = `
            UPDATE admin_users 
            SET password_hash = $1,
                otp = NULL,
                otp_expiry = NULL
            WHERE id = $2
        `;
        await db.query(updateQuery, [hashedPassword, admin.id]);

        // Send confirmation email
        const mailOptions = {
            from: {
                name: 'Security System',
                address: process.env.GMAIL_USER
            },
            to: admin.email,
            subject: 'Admin Password Reset Confirmation',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Password Reset Confirmation</title>
                </head>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background-color: #ffffff; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <h2 style="color: #2c3e50; margin-bottom: 20px;">Password Reset Successful</h2>
                        <p>Hello ${admin.username},</p>
                        <p>Your admin account password has been successfully reset.</p>
                        <p>If you didn't make this change, please contact the system administrator immediately.</p>
                        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
                            <p style="color: #666;">Best regards,<br>Security System Team</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        await transporter.sendMail(mailOptions);

        // Clear the reset token from localStorage
        res.json({ message: 'Password has been reset successfully' });
    } catch (error) {
        console.error('Reset password error:', error);
        if (error.name === 'JsonWebTokenError') {
            res.status(400).json({ error: 'Invalid or expired reset token' });
        } else {
            res.status(500).json({ error: 'Failed to reset password. Please try again.' });
        }
    }
});

// Get User Statistics
router.get('/user-statistics', verifyAdminToken, async (req, res) => {
    try {
        // console.log('Fetching user statistics...');

        // Get total users count from user_register table
        const totalUsersQuery = 'SELECT COUNT(*) as count FROM user_register';
        // console.log('Executing query:', totalUsersQuery);
        const totalUsersResult = await db.query(totalUsersQuery);
        // console.log('Total Users Result:', totalUsersResult.rows[0]);

        // Get blocked users count from login_attempts table
        const blockedUsersQuery = `
            SELECT COUNT(*) as count 
            FROM login_attempts 
            WHERE is_blocked = true 
            AND (block_expires_at IS NULL OR block_expires_at > CURRENT_TIMESTAMP)
        `;
        // console.log('Executing query:', blockedUsersQuery);
        const blockedUsersResult = await db.query(blockedUsersQuery);
        // console.log('Blocked Users Result:', blockedUsersResult.rows[0]);

        // Get active sessions count (users who logged in within last 30 minutes)
        const activeSessionsQuery = `
            SELECT COUNT(DISTINCT user_id) as count 
            FROM user_login 
            WHERE login_date > NOW() - INTERVAL '30 minutes'
        `;
        // console.log('Executing query:', activeSessionsQuery);
        const activeSessionsResult = await db.query(activeSessionsQuery);
        // console.log('Active Sessions Result:', activeSessionsResult.rows[0]);

        // Get users registered today
        const todayUsersQuery = `
            SELECT COUNT(*) as count 
            FROM user_register 
            WHERE DATE(created_at) = CURRENT_DATE
        `;
        // console.log('Executing query:', todayUsersQuery);
        const todayUsersResult = await db.query(todayUsersQuery);
        // console.log('Today Registrations Result:', todayUsersResult.rows[0]);

        // Verify we have valid results
        if (!totalUsersResult || !blockedUsersResult || !activeSessionsResult || !todayUsersResult) {
            throw new Error('One or more queries returned no results');
        }

        const statistics = {
            totalUsers: parseInt(totalUsersResult.rows[0]?.count) || 0,
            blockedUsers: parseInt(blockedUsersResult.rows[0]?.count) || 0,
            activeSessions: parseInt(activeSessionsResult.rows[0]?.count) || 0,
            todayRegistrations: parseInt(todayUsersResult.rows[0]?.count) || 0
        };

        // console.log('Final Statistics:', statistics);

        // Verify the statistics object
        if (Object.values(statistics).some(val => isNaN(val))) {
            throw new Error('Invalid statistics values detected');
        }

        res.json({ statistics });
    } catch (error) {
        console.error('User statistics fetch error:', error);
        console.error('Error stack:', error.stack);
        res.status(500).json({
            error: 'Internal server error',
            details: error.message
        });
    }
});

// Get All Users
router.get('/users', verifyAdminToken, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 8;
        const offset = (page - 1) * limit;

        // Get total count first
        const countQuery = `
            SELECT COUNT(*) as total
            FROM user_register ur
        `;
        const countResult = await db.query(countQuery);
        const totalUsers = parseInt(countResult.rows[0].total);

        // Get paginated users
        const query = `
            SELECT 
                ur.id,
                ur.username,
                ur.email,
                ur.register_method,
                ur.email_verified,
                ur.created_at,
                ul.login_date as last_login,
                COALESCE(ur.role, aua.role, 'user') as role
            FROM user_register ur
            LEFT JOIN user_login ul ON ur.id = ul.user_id
            LEFT JOIN added_user_by_admin aua ON ur.id = aua.user_id
            ORDER BY ur.created_at DESC
            LIMIT $1 OFFSET $2
        `;
        const result = await db.query(query, [limit, offset]);

        // Format the response
        const users = result.rows.map(user => ({
            id: user.id,
            username: user.username,
            email: user.email,
            registerMethod: user.register_method || 'manual',
            emailVerified: user.email_verified || false,
            createdAt: user.created_at,
            lastLogin: user.last_login,
            role: user.role
        }));

        res.json({
            users,
            pagination: {
                currentPage: page,
                totalPages: Math.ceil(totalUsers / limit),
                totalUsers,
                limit,
                hasNextPage: page < Math.ceil(totalUsers / limit),
                hasPrevPage: page > 1
            }
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get User Details
router.get('/users/:userId', verifyAdminToken, async (req, res) => {
    try {
        const userId = req.params.userId;

        // Get user registration details
        const userQuery = `
            SELECT 
                ur.*,
                ul.login_count,
                ul.login_date as last_login,
                ul.ip_address,
                ul.user_agent,
                COALESCE(fp.password_change_count, 0) as password_change_count,
                fp.password_change_date,
                fp.reset_token,
                fp.token_expiry,
                COALESCE(ur.role, aua.role, 'user') as role
            FROM user_register ur
            LEFT JOIN user_login ul ON ur.id = ul.user_id
            LEFT JOIN forgot_password fp ON ur.id = fp.user_id
            LEFT JOIN added_user_by_admin aua ON ur.id = aua.user_id
            WHERE ur.id = $1
        `;
        const userResult = await db.query(userQuery, [userId]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = userResult.rows[0];

        // Get user's login history
        const loginHistoryQuery = `
            SELECT 
                login_date,
                ip_address,
                user_agent
            FROM user_login
            WHERE user_id = $1
            ORDER BY login_date DESC
        `;
        const loginHistoryResult = await db.query(loginHistoryQuery, [userId]);

        // Get user's password reset history
        const resetHistoryQuery = `
            SELECT 
                password_change_date,
                password_change_count
            FROM forgot_password
            WHERE user_id = $1
            ORDER BY password_change_date DESC
        `;
        const resetHistoryResult = await db.query(resetHistoryQuery, [userId]);

        res.json({
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                registerMethod: user.register_method,
                emailVerified: user.email_verified,
                createdAt: user.created_at,
                loginCount: user.login_count || 0,
                lastLogin: user.last_login,
                ipAddress: formatIpAddress(user.ip_address),
                userAgent: user.user_agent,
                passwordChangeCount: user.password_change_count || 0,
                lastPasswordChange: user.password_change_date,
                resetToken: user.reset_token,
                resetTokenExpiry: user.token_expiry
            },
            loginHistory: loginHistoryResult.rows.map(login => ({
                ...login,
                ip_address: formatIpAddress(login.ip_address)
            })),
            resetHistory: resetHistoryResult.rows
        });
    } catch (error) {
        console.error('User details fetch error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete User
router.delete('/users/:userId', verifyAdminToken, async (req, res) => {
    try {
        const userId = req.params.userId;
        const adminId = req.admin.id; // Get admin ID from the verified token

        // First get user details before deletion
        const userDetails = await db.query(
            'SELECT username, email, register_method FROM user_register WHERE id = $1',
            [userId]
        );

        if (userDetails.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = userDetails.rows[0];

        // Begin transaction
        await db.query('BEGIN');

        try {
            // Record deletion in deleted_user_by_admin
            await db.query(
                `INSERT INTO deleted_user_by_admin 
                (admin_id, user_id, username, email, register_method, admin_ip_address, admin_user_agent) 
                VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [
                    adminId,
                    userId,
                    user.username,
                    user.email,
                    user.register_method,
                    req.ip,
                    req.headers['user-agent']
                ]
            );

            // Delete from login_attempts first (due to foreign key constraint)
            await db.query('DELETE FROM login_attempts WHERE user_id = $1', [userId]);

            // Delete from password_history
            await db.query('DELETE FROM password_history WHERE user_id = $1', [userId]);

            // Delete from otp_verification
            await db.query('DELETE FROM otp_verification WHERE user_id = $1', [userId]);

            // Delete from added_user_by_admin
            await db.query('DELETE FROM added_user_by_admin WHERE user_id = $1', [userId]);

            // Delete from user_login
            await db.query('DELETE FROM user_login WHERE user_id = $1', [userId]);

            // Delete from forgot_password
            await db.query('DELETE FROM forgot_password WHERE user_id = $1', [userId]);

            // Finally delete from user_register
            await db.query('DELETE FROM user_register WHERE id = $1', [userId]);

            // Commit transaction
            await db.query('COMMIT');

            res.json({ message: 'User deleted successfully' });
        } catch (error) {
            // Rollback transaction on error
            await db.query('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add User
router.post('/users', verifyAdminToken, async (req, res) => {
    try {
        const { username, email, password, registerMethod, role } = req.body;
        const adminId = req.admin.id; // Get admin ID from the verified token

        // Validate required fields
        if (!username || !email || !password || !role) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Validate role
        if (!['admin', 'user'].includes(role)) {
            return res.status(400).json({ error: 'Invalid role specified' });
        }

        // Check if username or email already exists
        const existingUser = await db.query(
            'SELECT id FROM user_register WHERE username = $1 OR email = $2',
            [username, email]
        );

        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }

        // Hash password
        const hashedPassword = await argon2.hash(password);
        const passwordExpiry = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000); // 90 days from now

        // Format IP address
        const ipAddress = req.ip === '::1' ? '127.0.0.1' : req.ip;

        // Begin transaction
        await db.query('BEGIN');

        try {
            // Insert into user_register (now includes role)
            const userResult = await db.query(
                `INSERT INTO user_register 
                (username, email, password_hash, register_method, email_verified, created_at, password_expiry, role) 
                VALUES ($1, $2, $3, $4, true, CURRENT_TIMESTAMP, $5, $6) 
                RETURNING id`,
                [username, email, hashedPassword, registerMethod || 'local', passwordExpiry, role]
            );

            const userId = userResult.rows[0].id;

            // Prepare metadata
            const metadata = {
                change_method: 'admin_creation',
                change_time: new Date().toISOString(),
                admin_id: adminId,
                ip_address: ipAddress,
                user_agent: req.headers['user-agent'] || 'Unknown'
            };

            // Store initial password in history
            await db.query(
                `INSERT INTO password_history 
                (user_id, password_hash, changed_by, metadata) 
                VALUES ($1, $2, $3, $4)`,
                [
                    userId,
                    hashedPassword,
                    'admin',
                    JSON.stringify(metadata)
                ]
            );

            // Record addition in added_user_by_admin
            await db.query(
                `INSERT INTO added_user_by_admin 
                (admin_id, user_id, username, email, register_method, role, admin_ip_address, admin_user_agent) 
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                [
                    adminId,
                    userId,
                    username,
                    email,
                    registerMethod || 'local',
                    role,
                    ipAddress,
                    req.headers['user-agent'] || 'Unknown'
                ]
            );

            // Initialize user_login record (set login_date to NULL and login_count to 0)
            await db.query(
                `INSERT INTO user_login 
                (user_id, username, email, password_hash, login_method, login_count, login_date, ip_address, user_agent) 
                VALUES ($1, $2, $3, $4, $5, 0, NULL, $6, $7)`,
                [
                    userId,
                    username,
                    email,
                    hashedPassword,
                    registerMethod || 'local',
                    ipAddress,
                    req.headers['user-agent'] || 'Unknown'
                ]
            );

            // Commit transaction
            await db.query('COMMIT');

            res.status(201).json({
                message: 'User created successfully',
                user: {
                    id: userId,
                    username,
                    email,
                    role,
                    registerMethod: registerMethod || 'local',
                    emailVerified: true
                }
            });
        } catch (error) {
            // Rollback transaction on error
            await db.query('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get audit logs with pagination and filters
router.get('/audit-logs', verifyAdminToken, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 7;
        const offset = (page - 1) * limit;

        const { actorType, action, startDate, endDate } = req.query;

        let query = `
            SELECT 
                al.*,
                CASE 
                    WHEN al.actor_type = 'admin' THEN au.email
                    ELSE ur.email
                END as target_email,
                CASE 
                    WHEN al.actor_type = 'admin' THEN au.username
                    ELSE ur.username
                END as target_username
            FROM audit_log al
            LEFT JOIN user_register ur ON al.actor_id = ur.id AND al.actor_type = 'user'
            LEFT JOIN admin_users au ON al.actor_id = au.id AND al.actor_type = 'admin'
            WHERE 1=1
        `;
        const queryParams = [];

        if (actorType) {
            queryParams.push(actorType);
            query += ` AND al.actor_type = $${queryParams.length}`;
        }

        if (action) {
            queryParams.push(action);
            query += ` AND al.action = $${queryParams.length}`;
        }

        if (startDate) {
            queryParams.push(startDate);
            query += ` AND al.event_time >= $${queryParams.length}`;
        }

        if (endDate) {
            queryParams.push(endDate);
            query += ` AND al.event_time <= $${queryParams.length}`;
        }

        // Add order by and pagination
        query += ` ORDER BY al.event_time DESC LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`;
        queryParams.push(limit, offset);

        // console.log('Query:', query); // Debug log
        // console.log('Params:', queryParams); // Debug log

        // Get total count for pagination
        let countQuery = `
            SELECT COUNT(*)
            FROM audit_log al
            LEFT JOIN user_register ur ON al.actor_id = ur.id AND al.actor_type = 'user'
            LEFT JOIN admin_users au ON al.actor_id = au.id AND al.actor_type = 'admin'
            WHERE 1=1
        `;

        const countParams = [];

        // Add the same filters to count query
        if (actorType) {
            countParams.push(actorType);
            countQuery += ` AND al.actor_type = $${countParams.length}`;
        }
        if (action) {
            countParams.push(action);
            countQuery += ` AND al.action = $${countParams.length}`;
        }
        if (startDate) {
            countParams.push(startDate);
            countQuery += ` AND al.event_time >= $${countParams.length}`;
        }
        if (endDate) {
            countParams.push(endDate);
            countQuery += ` AND al.event_time <= $${countParams.length}`;
        }

        const totalCount = await db.query(countQuery, countParams);

        const result = await db.query(query, queryParams);

        // console.log('Result rows:', result.rows); // Debug log

        const responseData = {
            logs: result.rows || [],
            totalPages: Math.ceil((totalCount.rows[0]?.count || 0) / limit),
            currentPage: page,
            totalLogs: parseInt(totalCount.rows[0]?.count || 0)
        };

        res.json(responseData);
    } catch (error) {
        console.error('Error fetching audit logs:', error);
        res.status(500).json({ error: 'Failed to fetch audit logs' });
    }
});

// Update user role
router.put('/users/:userId/role', verifyAdminToken, async (req, res) => {
    try {
        const { userId } = req.params;
        const { role } = req.body;

        // Validate role
        if (!role || !['admin', 'user'].includes(role)) {
            return res.status(400).json({ error: 'Invalid role specified' });
        }

        // Begin transaction
        await db.query('BEGIN');

        try {
            // Update role in user_register table
            const updateUserQuery = `
                UPDATE user_register 
                SET role = $1 
                WHERE id = $2
            `;
            await db.query(updateUserQuery, [role, userId]);

            // Update role in added_user_by_admin table
            const updateAdminQuery = `
                UPDATE added_user_by_admin 
                SET role = $1 
                WHERE user_id = $2
            `;
            await db.query(updateAdminQuery, [role, userId]);

            // Commit transaction
            await db.query('COMMIT');

            res.json({ message: 'User role updated successfully' });
        } catch (error) {
            // Rollback transaction on error
            await db.query('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Error updating user role:', error);
        res.status(500).json({ error: 'Failed to update user role' });
    }
});

// Verify Admin Password
router.post('/verify-password', verifyAdminToken, async (req, res) => {
    try {
        const { password } = req.body;
        const adminId = req.admin.id;

        // Get admin's password hash from admin_users table
        const result = await db.query(
            'SELECT password_hash FROM admin_users WHERE id = $1',
            [adminId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Admin not found' });
        }

        const { password_hash } = result.rows[0];

        // Verify password
        const validPassword = await argon2.verify(password_hash, password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid admin password' });
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error verifying admin password:', error);
        res.status(500).json({ error: 'Failed to verify admin password' });
    }
});

module.exports = router; 