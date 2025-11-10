import React, { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../../services/api';
import './AdminLogin.css';

const AdminResetPassword = () => {
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const token = searchParams.get('token');
    const [formData, setFormData] = useState({
        newPassword: '',
        confirmPassword: ''
    });
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(false);
    const [loading, setLoading] = useState(false);

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

        if (formData.newPassword !== formData.confirmPassword) {
            setError('Passwords do not match');
            setLoading(false);
            return;
        }

        try {
            const response = await api.adminResetPassword(token, formData.newPassword);
            if (response.error) {
                setError(response.error);
            } else {
                setSuccess(true);
                setTimeout(() => {
                    navigate('/admin-login-55x');
                }, 3000);
            }
        } catch (error) {
            setError('Failed to reset password. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    if (!token) {
        return (
            <div className="admin-login-container">
                <div className="admin-login-card">
                    <div className="alert alert-danger" role="alert">
                        Invalid or missing reset token. Please request a new password reset.
                    </div>
                    <button 
                        className="btn btn-primary w-100"
                        onClick={() => navigate('/admin-login-55x')}
                    >
                        Back to Login
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="admin-login-container">
            <div className="admin-login-card">
                <div className="text-center mb-4">
                    <h2 className="admin-login-title">Reset Admin Password</h2>
                    <p className="text-muted">Enter your new password</p>
                </div>

                {error && (
                    <div className="alert alert-danger" role="alert">
                        {error}
                    </div>
                )}

                {success && (
                    <div className="alert alert-success" role="alert">
                        Password has been reset successfully. Redirecting to login...
                    </div>
                )}

                {!success && (
                    <form onSubmit={handleSubmit}>
                        <div className="mb-3">
                            <label htmlFor="newPassword" className="form-label">New Password</label>
                            <input
                                type="password"
                                className="form-control"
                                id="newPassword"
                                name="newPassword"
                                value={formData.newPassword}
                                onChange={handleChange}
                                required
                                minLength="8"
                            />
                        </div>
                        <div className="mb-3">
                            <label htmlFor="confirmPassword" className="form-label">Confirm Password</label>
                            <input
                                type="password"
                                className="form-control"
                                id="confirmPassword"
                                name="confirmPassword"
                                value={formData.confirmPassword}
                                onChange={handleChange}
                                required
                                minLength="8"
                            />
                        </div>
                        <div className="d-grid gap-2">
                            <button 
                                type="submit" 
                                className="btn btn-primary"
                                disabled={loading}
                            >
                                {loading ? (
                                    <>
                                        <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                                        Resetting Password...
                                    </>
                                ) : 'Reset Password'}
                            </button>
                        </div>
                    </form>
                )}
            </div>
        </div>
    );
};

export default AdminResetPassword; 