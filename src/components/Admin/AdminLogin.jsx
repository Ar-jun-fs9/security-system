import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';
import './AdminLogin.css';
import { FaEye, FaEyeSlash, FaUserShield } from 'react-icons/fa';

const AdminLogin = () => {
    const navigate = useNavigate();
    const [formData, setFormData] = useState({
        username: '',
        password: ''
    });
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);
    const [showForgotPassword, setShowForgotPassword] = useState(false);
    const [forgotPasswordEmail, setForgotPasswordEmail] = useState('');
    const [forgotPasswordStatus, setForgotPasswordStatus] = useState(null);
    const [otp, setOtp] = useState('');
    const [showOtpField, setShowOtpField] = useState(false);
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showNewPasswordField, setShowNewPasswordField] = useState(false);
    const [showPassword, setShowPassword] = useState(false);
    const [showNewPassword, setShowNewPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setLoading(true);

        try {
            const response = await api.adminLogin(formData.username, formData.password);
            if (response.error) {
                setError(response.error);
                // Reset form fields on error
                // setFormData({
                //     username: '',
                //     password: ''
                // });
                // Hide error message after 3 seconds
                setTimeout(() => {
                    setError(null);
                }, 1000);
            } else {
                localStorage.setItem('adminToken', response.token);
                navigate('/admin-dashboard');
            }
        } catch (error) {
            setError('Failed to login. Please try again.');
            // Reset form fields on error
            setFormData({
                username: '',
                password: ''
            });
            // Hide error message after 3 seconds
            setTimeout(() => {
                setError(null);
            }, 1000);
        } finally {
            setLoading(false);
        }
    };

    const handleForgotPassword = async (e) => {
        e.preventDefault();
        setForgotPasswordStatus(null);

        try {
            const response = await api.adminForgotPassword(forgotPasswordEmail);
            if (response.error) {
                setForgotPasswordStatus({ type: 'error', message: response.error });
            } else {
                setForgotPasswordStatus({ 
                    type: 'success', 
                    message: 'Password reset OTP has been sent to your email.' 
                });
                setShowOtpField(true);
            }
        } catch (error) {
            setForgotPasswordStatus({ 
                type: 'error', 
                message: 'Failed to process request. Please try again.' 
            });
        }
    };

    const handleVerifyOtp = async (e) => {
        e.preventDefault();
        setForgotPasswordStatus(null);

        try {
            const response = await api.adminVerifyOTP(forgotPasswordEmail, otp);
            if (response.error) {
                setForgotPasswordStatus({ type: 'error', message: response.error });
            } else {
                setForgotPasswordStatus({ 
                    type: 'success', 
                    message: 'OTP verified successfully. Please enter your new password.' 
                });
                localStorage.setItem('adminResetToken', response.resetToken);
                setShowOtpField(false);
                setShowNewPasswordField(true);
            }
        } catch (error) {
            setForgotPasswordStatus({ 
                type: 'error', 
                message: 'Failed to verify OTP. Please try again.' 
            });
        }
    };

    const handleResetPassword = async (e) => {
        e.preventDefault();
        setForgotPasswordStatus(null);

        if (newPassword !== confirmPassword) {
            setForgotPasswordStatus({ 
                type: 'error', 
                message: 'Passwords do not match!' 
            });
            return;
        }

        if (newPassword.length < 8) {
            setForgotPasswordStatus({ 
                type: 'error', 
                message: 'Password must be at least 8 characters long!' 
            });
            return;
        }

        try {
            const response = await api.adminResetPassword(newPassword);
            if (response.error) {
                setForgotPasswordStatus({ type: 'error', message: response.error });
            } else {
                setForgotPasswordStatus({ 
                    type: 'success', 
                    message: 'Password has been reset successfully!' 
                });
                localStorage.removeItem('adminResetToken');
                setTimeout(() => {
                    setShowForgotPassword(false);
                    setShowOtpField(false);
                    setShowNewPasswordField(false);
                    setForgotPasswordEmail('');
                    setOtp('');
                    setNewPassword('');
                    setConfirmPassword('');
                }, 2000);
            }
        } catch (error) {
            setForgotPasswordStatus({ 
                type: 'error', 
                message: error.message || 'Failed to reset password. Please try again.' 
            });
        }
    };

    return (
        <div className="admin-login-container">
            <div className="admin-login-card">
                <div className="admin-login-header">
                    <FaUserShield className="admin-icon" />
                    <h2 className="admin-login-title">Admin Login Portal</h2>
                    <p className="admin-login-subtitle">Secure Access Control</p>
                </div>

                {error && (
                    <div className="alert alert-danger" role="alert">
                        {error}
                    </div>
                )}

                {!showForgotPassword ? (
                    <form onSubmit={handleSubmit} className="admin-login-form">
                        <div className="form-group">
                            <label htmlFor="username" className="form-label">Username</label>
                            <div className="input-group">
                                <input
                                    type="text"
                                    // autoComplete='off'
                                    className="form-control"
                                    id="username"
                                    name="username"
                                    value={formData.username}
                                    onChange={handleChange}
                                    placeholder="Enter your username"
                                    required
                                />
                            </div>
                        </div>
                        <div className="form-group">
                            <label htmlFor="password" className="form-label">Password</label>
                            <div className="input-group">
                                <input
                                    type={showPassword ? "text" : "password"}
                                    className="form-control"
                                    id="password"
                                    name="password"
                                    value={formData.password}
                                    onChange={handleChange}
                                    placeholder="Enter your password"
                                    required
                                />
                                <button
                                    type="button"
                                    className="password-toggle-btn"
                                    onClick={() => setShowPassword(!showPassword)}
                                >
                                    {showPassword ? <FaEyeSlash /> : <FaEye />}
                                </button>
                            </div>
                        </div>
                        <div className="d-grid gap-2">
                            <button type="submit" className="btn btn-primary admin-login-btn" disabled={loading}>
                                {loading ? 'Authenticating...' : 'Sign In'}
                            </button>
                        </div>
                        <div className="text-center mt-3">
                            <button 
                                type="button" 
                                className="btn btn-link forgot-password-link"
                                onClick={() => setShowForgotPassword(true)}
                            >
                                Forgot Password?
                            </button>
                        </div>
                    </form>
                ) : (
                    <form onSubmit={showNewPasswordField ? handleResetPassword : (showOtpField ? handleVerifyOtp : handleForgotPassword)} className="admin-login-form">
                        {!showOtpField && !showNewPasswordField ? (
                            <>
                                <div className="form-group">
                                    <label htmlFor="email" className="form-label">Admin Email</label>
                                    <input
                                        type="email"
                                        className="form-control"
                                        id="email"
                                        value={forgotPasswordEmail}
                                        onChange={(e) => setForgotPasswordEmail(e.target.value)}
                                        placeholder="Enter your admin email"
                                        required
                                    />
                                </div>
                                {forgotPasswordStatus && (
                                    <div className={`alert alert-${forgotPasswordStatus.type}`} role="alert">
                                        {forgotPasswordStatus.message}
                                    </div>
                                )}
                                <div className="d-grid gap-2">
                                    <button type="submit" className="btn btn-primary admin-login-btn">
                                        Send Reset OTP
                                    </button>
                                </div>
                            </>
                        ) : showOtpField ? (
                            <>
                                <div className="form-group">
                                    <label htmlFor="otp" className="form-label">Enter OTP</label>
                                    <input
                                        type="text"
                                        className="form-control"
                                        id="otp"
                                        value={otp}
                                        onChange={(e) => setOtp(e.target.value)}
                                        required
                                        maxLength="6"
                                        placeholder="Enter 6-digit OTP"
                                    />
                                </div>
                                {forgotPasswordStatus && (
                                    <div className={`alert alert-${forgotPasswordStatus.type}`} role="alert">
                                        {forgotPasswordStatus.message}
                                    </div>
                                )}
                                <div className="d-grid gap-2">
                                    <button type="submit" className="btn btn-primary admin-login-btn">
                                        Verify OTP
                                    </button>
                                </div>
                            </>
                        ) : (
                            <>
                                <div className="form-group">
                                    <label htmlFor="newPassword" className="form-label">New Password</label>
                                    <div className="input-group">
                                        <input
                                            type={showNewPassword ? "text" : "password"}
                                            className="form-control"
                                            id="newPassword"
                                            value={newPassword}
                                            onChange={(e) => setNewPassword(e.target.value)}
                                            required
                                            minLength="8"
                                            placeholder="Enter new password"
                                        />
                                        <button
                                            type="button"
                                            className="password-toggle-btn"
                                            onClick={() => setShowNewPassword(!showNewPassword)}
                                        >
                                            {showNewPassword ? <FaEyeSlash /> : <FaEye />}
                                        </button>
                                    </div>
                                </div>
                                <div className="form-group">
                                    <label htmlFor="confirmPassword" className="form-label">Confirm Password</label>
                                    <div className="input-group">
                                        <input
                                            type={showConfirmPassword ? "text" : "password"}
                                            className="form-control"
                                            id="confirmPassword"
                                            value={confirmPassword}
                                            onChange={(e) => setConfirmPassword(e.target.value)}
                                            required
                                            minLength="8"
                                            placeholder="Confirm new password"
                                        />
                                        <button
                                            type="button"
                                            className="password-toggle-btn"
                                            onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                        >
                                            {showConfirmPassword ? <FaEyeSlash /> : <FaEye />}
                                        </button>
                                    </div>
                                </div>
                                {forgotPasswordStatus && (
                                    <div className={`alert alert-${forgotPasswordStatus.type}`} role="alert">
                                        {forgotPasswordStatus.message}
                                    </div>
                                )}
                                <div className="d-grid gap-2">
                                    <button type="submit" className="btn btn-primary admin-login-btn">
                                        Reset Password
                                    </button>
                                </div>
                            </>
                        )}
                        <div className="text-center mt-3">
                            <button 
                                type="button" 
                                className="btn btn-link back-to-login-link"
                                onClick={() => {
                                    setShowForgotPassword(false);
                                    setShowOtpField(false);
                                    setShowNewPasswordField(false);
                                    setForgotPasswordEmail('');
                                    setOtp('');
                                    setNewPassword('');
                                    setConfirmPassword('');
                                    setForgotPasswordStatus(null);
                                }}
                            >
                                Back to Login
                            </button>
                        </div>
                    </form>
                )}
            </div>
        </div>
    );
};

export default AdminLogin; 