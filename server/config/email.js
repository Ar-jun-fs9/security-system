const nodemailer = require('nodemailer');
const crypto = require('crypto');

// Encryption key and IV (store these securely in environment variables in production)
if (!process.env.ENCRYPTION_KEY) {
    throw new Error('ENCRYPTION_KEY is not set in environment variables');
}

// Ensure the key is exactly 32 bytes
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
if (ENCRYPTION_KEY.length !== 32) {
    throw new Error('ENCRYPTION_KEY must be 32 bytes (64 hex characters)');
}

const IV_LENGTH = 16;

// Function to encrypt token
const encryptToken = (token) => {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(token);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
};

// Create and export the transporter
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

const sendVerificationEmail = async (email, username, verificationToken) => {
    try {
        console.log('Original verification token:', verificationToken);

        // Encrypt the token
        const encryptedToken = encryptToken(verificationToken);
        console.log('Encrypted token:', encryptedToken);

        const verificationUrl = `http://localhost:5173/verify-email?token=${encodeURIComponent(encryptedToken)}`;
        console.log('Verification URL:', verificationUrl);

        const mailOptions = {
            from: {
                name: 'Security System',
                address: process.env.GMAIL_USER
            },
            to: email,
            subject: 'Verify your email address',
            headers: {
                'X-Priority': '1',
                'X-MSMail-Priority': 'High',
                'Importance': 'high',
                'X-Mailer': 'Security System Mailer',
                'List-Unsubscribe': `<mailto:${process.env.GMAIL_USER}?subject=unsubscribe>`,
                'Precedence': 'bulk',
                'X-Auto-Response-Suppress': 'OOF, AutoReply'
            },
            dsn: {
                id: 'verification-email',
                return: 'headers',
                notify: ['failure', 'delay'],
                recipient: process.env.GMAIL_USER
            },
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Email Verification</title>
                </head>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background-color: #ffffff; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <div style="text-align: center; margin-bottom: 30px;">
                            <h2 style="color: #2c3e50; margin-bottom: 10px;">Hey ${username},</h2>
                            <p style="font-size: 16px; color: #666;">You're almost in!</p>
                        </div>
                        
                        <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                            <p style="margin: 10px 0; color: #2c3e50;">
                                <span style="color: #27ae60;">✅</span> Industry-leading security features
                            </p>
                            <p style="margin: 10px 0; color: #2c3e50;">
                                <span style="color: #27ae60;">✅</span> Advanced authentication system
                            </p>
                            <p style="margin: 10px 0; color: #2c3e50;">
                                <span style="color: #27ae60;">✅</span> Real-time monitoring
                            </p>
                            <p style="margin: 10px 0; color: #2c3e50;">
                                <span style="color: #27ae60;">✅</span> User-friendly interface
                            </p>
                        </div>

                        <p style="text-align: center; margin: 30px 0;">
                            <a href="${verificationUrl}" 
                               style="display: inline-block; background-color: #3498db; color: white; padding: 14px 28px; 
                                      text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 16px;">
                                👉 Confirm My Email
                            </a>
                        </p>

                        <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
                            <p style="color: #666; margin: 5px 0;">See you inside,</p>
                            <p style="color: #2c3e50; font-weight: bold; margin: 5px 0;">The Security System Team</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent successfully:', info.messageId);
        return true;
    } catch (error) {
        console.error('Error sending verification email:', error);
        return false;
    }
};

module.exports = {
    sendVerificationEmail,
    encryptToken,
    transporter
}; 