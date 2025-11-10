import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';
import zxcvbn from 'zxcvbn';
import './Dashboard.css';
import LogoutConfirmationModal from '../Common/LogoutConfirmationModal';
import ProfileUpdateModal from './ProfileUpdateModal';

const UserDashboard = () => {
    const navigate = useNavigate();
    const [userData, setUserData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [resendStatus, setResendStatus] = useState(null);
    const [activeTab, setActiveTab] = useState('profile');
    const [activeSecurityOption, setActiveSecurityOption] = useState(null);
    const [isSidebarOpen, setIsSidebarOpen] = useState(true);
    const [isSettingsOpen, setIsSettingsOpen] = useState(false);
    const [passwordData, setPasswordData] = useState({
        oldPassword: '',
        newPassword: '',
        confirmPassword: ''
    });
    const [showOldPassword, setShowOldPassword] = useState(false);
    const [showNewPassword, setShowNewPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);
    const [passwordStrength, setPasswordStrength] = useState(0);
    const [passwordError, setPasswordError] = useState(null);
    const [passwordSuccess, setPasswordSuccess] = useState(null);
    const [showLogoutConfirm, setShowLogoutConfirm] = useState(false);
    const [showPasswordExpiryWarning, setShowPasswordExpiryWarning] = useState(false);
    const [showProfileUpdateModal, setShowProfileUpdateModal] = useState(false);

    useEffect(() => {
        const token = localStorage.getItem('token');
        if (!token) {
            navigate('/auth?tab=login');
            return;
        }

        fetchUserData();
    }, [navigate]);

    useEffect(() => {
        if (passwordData.newPassword) {
            const result = zxcvbn(passwordData.newPassword);
            setPasswordStrength(result.score);
        } else {
            setPasswordStrength(0);
        }
    }, [passwordData.newPassword]);

    const fetchUserData = async () => {
        try {
            const response = await api.getUserProfile();
            if (response.error) {
                setError(response.error);
            } else {
                setUserData(response);
                // Check password expiry
                if (response.password_expiry) {
                    const now = new Date();
                    const expiry = new Date(response.password_expiry);
                    const daysUntilExpiry = Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
                    
                    if (daysUntilExpiry <= 7) {
                        setShowPasswordExpiryWarning(true);
                    }
                }
            }
        } catch (error) {
            setError('Failed to fetch user data');
        } finally {
            setLoading(false);
        }
    };

    const handleLogout = () => {
        setShowLogoutConfirm(true);
    };

    const handleLogoutConfirm = () => {
        localStorage.removeItem('token');
        navigate('/auth?tab=login');
    };

    const handleLogoutCancel = () => {
        setShowLogoutConfirm(false);
    };

    const handleResendVerification = async () => {
        try {
            const response = await api.resendVerification(userData.email);
            if (response.error) {
                setResendStatus({ type: 'error', message: response.error });
            } else {
                setResendStatus({ type: 'success', message: 'Verification email sent successfully' });
            }
        } catch (error) {
            setResendStatus({ type: 'error', message: 'Failed to resend verification email' });
        }
    };

    const handlePasswordChange = async (e) => {
        e.preventDefault();
        setPasswordError(null);
        setPasswordSuccess(null);

        if (passwordData.newPassword !== passwordData.confirmPassword) {
            setPasswordError('New passwords do not match');
            setTimeout(() => {
                setPasswordError(null);
                setPasswordData({
                    oldPassword: '',
                    newPassword: '',
                    confirmPassword: ''
                });
                setShowOldPassword(false);
                setShowNewPassword(false);
                setShowConfirmPassword(false);
            }, 2000);
            return;
        }

        if (passwordStrength < 2) {
            setPasswordError('Password is too weak');
            setTimeout(() => {
                setPasswordError(null);
                setPasswordData({
                    oldPassword: '',
                    newPassword: '',
                    confirmPassword: ''
                });
                setShowOldPassword(false);
                setShowNewPassword(false);
                setShowConfirmPassword(false);
            }, 2000);
            return;
        }

        try {
            const response = await api.changePassword(userData.email, passwordData.newPassword);
            if (response.error) {
                setPasswordError(response.error);
                setTimeout(() => {
                    setPasswordError(null);
                    setPasswordData({
                        oldPassword: '',
                        newPassword: '',
                        confirmPassword: ''
                    });
                    setShowOldPassword(false);
                    setShowNewPassword(false);
                    setShowConfirmPassword(false);
                }, 2000);
            } else {
                setPasswordSuccess('Password changed successfully');
                setTimeout(() => {
                    setPasswordSuccess(null);
                    setPasswordData({
                        oldPassword: '',
                        newPassword: '',
                        confirmPassword: ''
                    });
                    setShowOldPassword(false);
                    setShowNewPassword(false);
                    setShowConfirmPassword(false);
                }, 2000);
            }
        } catch (error) {
            setPasswordError('Failed to change password');
            setTimeout(() => {
                setPasswordError(null);
                setPasswordData({
                    oldPassword: '',
                    newPassword: '',
                    confirmPassword: ''
                });
                setShowOldPassword(false);
                setShowNewPassword(false);
                setShowConfirmPassword(false);
            }, 2000);
        }
    };

    const maskEmail = (email) => {
        const [username, domain] = email.split('@');
        const maskedUsername = username.charAt(0) + '*'.repeat(username.length - 1);
        return `${maskedUsername}@${domain}`;
    };

    const getPasswordStrengthLabel = (score) => {
        const labels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
        const colors = ['danger', 'warning', 'info', 'primary', 'success'];
        return {
            label: labels[score],
            color: colors[score]
        };
    };

    const getDeviceInfo = (userAgent) => {
        if (!userAgent) return 'Unknown';
        
        // Basic device detection
        const isMobile = /Mobile|Android|iP(hone|od)|IEMobile|BlackBerry|Kindle|Silk-Accelerated|(hpw|web)OS|Opera M(obi|ini)/.test(userAgent);
        const isTablet = /(tablet|ipad|playbook|silk)|(android(?!.*mobi))/i.test(userAgent);
        
        if (isMobile) return 'Mobile Device';
        if (isTablet) return 'Tablet';
        return 'Desktop';
    };

    const getBrowserInfo = (userAgent) => {
        if (!userAgent) return 'Unknown';
        
        // Basic browser detection
        if (userAgent.includes('Chrome')) return 'Chrome';
        if (userAgent.includes('Firefox')) return 'Firefox';
        if (userAgent.includes('Safari')) return 'Safari';
        if (userAgent.includes('Edge')) return 'Edge';
        if (userAgent.includes('MSIE') || userAgent.includes('Trident/')) return 'Internet Explorer';
        return 'Other Browser';
    };

    const formatIpAddress = (ip) => {
        if (!ip) return 'N/A';
        if (ip === '::1') return 'Localhost (127.0.0.1)';
        if (ip.startsWith('::ffff:')) return ip.replace('::ffff:', ''); // Convert IPv4-mapped IPv6 to IPv4
        return ip;
    };

    const toggleSidebar = () => {
        setIsSidebarOpen(!isSidebarOpen);
    };

    const toggleSettings = () => {
        setIsSettingsOpen(!isSettingsOpen);
    };

    const handleProfileUpdate = () => {
        setShowProfileUpdateModal(true);
    };

    const handleProfileUpdateClose = () => {
        setShowProfileUpdateModal(false);
    };

    const handleProfileUpdateSuccess = (updatedUser) => {
        setUserData(prev => ({
            ...prev,
            username: updatedUser.username,
            email: updatedUser.email
        }));
    };

    if (loading) {
        return (
            <div className="dashboard-loading">
                <div className="spinner-border text-primary" role="status">
                    <span className="visually-hidden">Loading...</span>
                </div>
                <p className="mt-3">Loading user data...</p>
            </div>
        );
    }

    if (error) {
        return (
            <div className="dashboard-error">
                <div className="alert alert-danger" role="alert">
                    {error}
                </div>
            </div>
        );
    }

    return (
        <div className="dashboard-container">
            {showPasswordExpiryWarning && (
                <div className="alert alert-warning alert-dismissible fade show" role="alert">
                    <strong>Password Expiry Warning!</strong> Your password will expire soon. Please change it to maintain account security.
                    <button type="button" className="btn-close" onClick={() => setShowPasswordExpiryWarning(false)}></button>
                </div>
            )}

            {/* Sidebar */}
            <div className={`dashboard-sidebar ${isSidebarOpen ? 'open' : 'closed'} shadow-sm`}>
                <div className="sidebar-header bg-white">
                    <h3 className="mb-0">Dashboard</h3>
                    <button className="btn btn-link text-muted p-0" onClick={toggleSidebar}>
                        <i className={`fas fa-chevron-${isSidebarOpen ? 'left' : 'right'}`}></i>
                    </button>
                </div>
                <div className="sidebar-content">
                    <div className="user-info bg-white">
                        <div className="user-avatar">
                            <i className="fas fa-user-circle"></i>
                        </div>
                        <div className="user-details">
                            <h4 className="mb-1">{userData.username}</h4>
                            <p className="text-muted small mb-0">{maskEmail(userData.email)}</p>
                        </div>
                    </div>
                    <nav className="sidebar-nav">
                        <button 
                            className={`nav-item ${activeTab === 'profile' ? 'active' : ''}`}
                            onClick={() => setActiveTab('profile')}
                        >
                            <i className="fas fa-user"></i>
                            <span>Profile</span>
                        </button>
                        <button 
                            className={`nav-item ${activeTab === 'security' ? 'active' : ''}`}
                            onClick={() => setActiveTab('security')}
                        >
                            <i className="fas fa-shield-alt"></i>
                            <span>Security</span>
                        </button>
                        <button 
                            className={`nav-item ${activeTab === 'history' ? 'active' : ''}`}
                            onClick={() => setActiveTab('history')}
                        >
                            <i className="fas fa-history"></i>
                            <span>Login History</span>
                        </button>
                    </nav>
                </div>
            </div>

            {/* Main Content */}
            <div className="dashboard-main">
                <div className="dashboard-header bg-white shadow-sm">
                    <button className="btn btn-link text-muted p-0 menu-toggle" onClick={toggleSidebar}>
                        <i className="fas fa-bars"></i>
                    </button>
                    <div className="header-actions">
                        <button className="btn btn-link text-muted p-0 settings-toggle" onClick={toggleSettings}>
                            <i className="fas fa-cog"></i>
                        </button>
                        <button className="btn btn-danger btn-sm" onClick={handleLogout}>
                            <i className="fas fa-sign-out-alt me-2"></i>
                            Logout
                        </button>
                    </div>
                </div>

                <div className="dashboard-content">
                    {!userData.email_verified && (
                        <div className="alert alert-warning mb-4">
                            <h5 className="alert-heading">Email Not Verified</h5>
                            <p className="mb-0">Please verify your email address to access all features.</p>
                            <hr />
                            <button 
                                className="btn btn-warning"
                                onClick={handleResendVerification}
                            >
                                Resend Verification Email
                            </button>
                        </div>
                    )}

                    {resendStatus && (
                        <div className={`alert alert-${resendStatus.type === 'success' ? 'success' : 'danger'} mb-4`}>
                            {resendStatus.message}
                        </div>
                    )}

                    {/* Profile Tab */}
                    {activeTab === 'profile' && (
                        <div className="row g-4">
                            <div className="col-md-6">
                                <div className="card h-100 shadow-sm">
                                    <div className="card-body">
                                        <div className="d-flex justify-content-between align-items-center mb-4">
                                            <h3 className="card-title mb-0">
                                            <i className="fas fa-user-circle me-2 text-primary"></i>
                                            Profile Information
                                        </h3>
                                            <button 
                                                className="btn btn-outline-primary btn-sm"
                                                onClick={handleProfileUpdate}
                                            >
                                                <i className="fas fa-edit me-2"></i>
                                                Update Profile
                                            </button>
                                        </div>
                                        <div className="profile-info">
                                            <div className="info-item">
                                                <label>Username</label>
                                                <p>{userData.username}</p>
                                            </div>
                                            <div className="info-item">
                                                <label>Email</label>
                                                <p>{maskEmail(userData.email)}</p>
                                            </div>
                                            <div className="info-item">
                                                <label>Registration Method</label>
                                                <p className="text-capitalize">{userData.register_method}</p>
                                            </div>
                                            <div className="info-item">
                                                <label>Account Created</label>
                                                <p>{new Date(userData.created_at).toLocaleDateString()}</p>
                                            </div>
                                            <div className="info-item">
                                                <label>Email Status</label>
                                                <p>
                                                    <span className={`badge text-white ${userData.email_verified ? 'bg-success' : 'bg-warning'}`}>
                                                        {userData.email_verified ? 'Verified' : 'Not Verified'}
                                                    </span>
                                                </p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div className="col-md-6">
                                <div className="card h-100 shadow-sm">
                                    <div className="card-body">
                                        <h3 className="card-title mb-4">
                                            <i className="fas fa-chart-line me-2 text-primary"></i>
                                            Account Statistics
                                        </h3>
                                        <div className="stats-grid">
                                            <div className="stat-card">
                                                <div className="stat-icon bg-info">
                                                    <i className="fas fa-sign-in-alt"></i>
                                                </div>
                                                <div className="stat-info">
                                                    <h4>Last Login</h4>
                                                    <p>{new Date(userData.login_history?.login_date).toLocaleString()}</p>
                                                </div>
                                            </div>
                                            <div className="stat-card">
                                                <div className="stat-icon bg-warning">
                                                    <i className="fas fa-shield-alt"></i>
                                                </div>
                                                <div className="stat-info">
                                                    <h4 className='mb-2'>Security Status</h4>
                                                    <p className="badge bg-warning text-white">Protected</p>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Security Tab */}
                    {activeTab === 'security' && (
                        <div className="row g-4">
                            {!activeSecurityOption ? (
                                <>
                                    <div className="col-md-6 col-lg-3">
                                        <div className="card h-100 shadow-sm security-card" onClick={() => setActiveSecurityOption('password')}>
                                            <div className="card-body text-center">
                                                <div className="security-icon bg-primary">
                                                    <i className="fas fa-key"></i>
                                                </div>
                                                <h4 className="mt-3 mb-2">Change Password</h4>
                                                <p className="text-muted mb-0">Update your account password</p>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="col-md-6 col-lg-3">
                                        <div className="card h-100 shadow-sm security-card" onClick={() => setActiveSecurityOption('2fa')}>
                                            <div className="card-body text-center">
                                                <div className="security-icon bg-success">
                                                    <i className="fas fa-shield-alt"></i>
                                                </div>
                                                <h4 className="mt-3 mb-2">Two-Factor Auth</h4>
                                                <p className="text-muted mb-0">Add extra security layer</p>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="col-md-6 col-lg-3">
                                        <div className="card h-100 shadow-sm security-card" onClick={() => setActiveSecurityOption('recovery')}>
                                            <div className="card-body text-center">
                                                <div className="security-icon bg-info">
                                                    <i className="fas fa-envelope"></i>
                                                </div>
                                                <h4 className="mt-3 mb-2">Recovery Email</h4>
                                                <p className="text-muted mb-0">Set up recovery options</p>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="col-md-6 col-lg-3">
                                        <div className="card h-100 shadow-sm security-card" onClick={() => setActiveSecurityOption('sessions')}>
                                            <div className="card-body text-center">
                                                <div className="security-icon bg-warning">
                                                    <i className="fas fa-desktop"></i>
                                                </div>
                                                <h4 className="mt-3 mb-2">Active Sessions</h4>
                                                <p className="text-muted mb-0">Manage your sessions</p>
                                            </div>
                                        </div>
                                    </div>
                                </>
                            ) : (
                                <div className="col-12">
                                    <div className="card shadow-sm">
                                        <div className="card-body">
                                            <button 
                                                className="btn btn-link text-decoration-none mb-3"
                                                onClick={() => setActiveSecurityOption(null)}
                                            >
                                                <i className="fas fa-arrow-left me-2"></i>
                                                Back to Security Options
                                            </button>

                                            {activeSecurityOption === 'password' && (
                                                <form onSubmit={handlePasswordChange}>
                                                    <div className="row">
                                                        <div className="col-md-6">
                                                            <div className="form-group">
                                                                <label className="form-label">Current Password</label>
                                                                <div className="password-input-container">
                                                                <input
                                                                        type={showOldPassword ? "text" : "password"}
                                                                    className="form-control"
                                                                    value={passwordData.oldPassword}
                                                                    onChange={(e) => setPasswordData({ ...passwordData, oldPassword: e.target.value })}
                                                                    required
                                                                />
                                                                    <button
                                                                        type="button"
                                                                        className="password-toggle"
                                                                        onClick={() => setShowOldPassword(!showOldPassword)}
                                                                    >
                                                                        <i className={`fas fa-${showOldPassword ? "eye-slash" : "eye"}`}></i>
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                        <div className="col-md-6">
                                                            <div className="form-group">
                                                                <label className="form-label">New Password</label>
                                                                <div className="password-input-container">
                                                                <input
                                                                        type={showNewPassword ? "text" : "password"}
                                                                    className="form-control"
                                                                    value={passwordData.newPassword}
                                                                    onChange={(e) => setPasswordData({ ...passwordData, newPassword: e.target.value })}
                                                                    required
                                                                />
                                                                    <button
                                                                        type="button"
                                                                        className="password-toggle"
                                                                        onClick={() => setShowNewPassword(!showNewPassword)}
                                                                    >
                                                                        <i className={`fas fa-${showNewPassword ? "eye-slash" : "eye"}`}></i>
                                                                    </button>
                                                                </div>
                                                                {passwordData.newPassword && (
                                                                    <div className="mt-2">
                                                                        <div className="progress" style={{ height: '5px' }}>
                                                                            <div
                                                                                className={`progress-bar bg-${getPasswordStrengthLabel(passwordStrength).color}`}
                                                                                role="progressbar"
                                                                                style={{ width: `${(passwordStrength + 1) * 25}%` }}
                                                                            />
                                                                        </div>
                                                                        <small className={`text-${getPasswordStrengthLabel(passwordStrength).color}`}>
                                                                            {getPasswordStrengthLabel(passwordStrength).label}
                                                                        </small>
                                                                    </div>
                                                                )}
                                                            </div>
                                                        </div>
                                                        <div className="col-md-6">
                                                            <div className="form-group">
                                                                <label className="form-label">Confirm New Password</label>
                                                                <div className="password-input-container">
                                                                <input
                                                                        type={showConfirmPassword ? "text" : "password"}
                                                                    className="form-control"
                                                                    value={passwordData.confirmPassword}
                                                                    onChange={(e) => setPasswordData({ ...passwordData, confirmPassword: e.target.value })}
                                                                    required
                                                                />
                                                                    <button
                                                                        type="button"
                                                                        className="password-toggle"
                                                                        onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                                                    >
                                                                        <i className={`fas fa-${showConfirmPassword ? "eye-slash" : "eye"}`}></i>
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    {passwordError && (
                                                        <div className="alert alert-danger mt-3">{passwordError}</div>
                                                    )}
                                                    {passwordSuccess && (
                                                        <div className="alert alert-success mt-3">{passwordSuccess}</div>
                                                    )}
                                                    <button type="submit" className="btn btn-primary mt-3">
                                                        Change Password
                                                    </button>
                                                </form>
                                            )}

                                            {activeSecurityOption === '2fa' && (
                                                <div className="coming-soon text-center py-5">
                                                    <i className="fas fa-shield-alt fa-3x text-muted mb-3"></i>
                                                    <h4>Two-Factor Authentication</h4>
                                                    <p className="text-muted">This feature will be available soon.</p>
                                                </div>
                                            )}

                                            {activeSecurityOption === 'recovery' && (
                                                <div className="coming-soon text-center py-5">
                                                    <i className="fas fa-envelope fa-3x text-muted mb-3"></i>
                                                    <h4>Recovery Email</h4>
                                                    <p className="text-muted">This feature will be available soon.</p>
                                                </div>
                                            )}

                                            {activeSecurityOption === 'sessions' && (
                                                <div className="coming-soon text-center py-5">
                                                    <i className="fas fa-desktop fa-3x text-muted mb-3"></i>
                                                    <h4>Active Sessions</h4>
                                                    <p className="text-muted">This feature will be available soon.</p>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    {/* History Tab */}
                    {activeTab === 'history' && userData.login_history && (
                        <div className="card shadow-sm">
                            <div className="card-body">
                                <h3 className="card-title mb-4">
                                    <i className="fas fa-history me-2 text-primary"></i>
                                    Login History
                                </h3>
                                <div className="table-responsive">
                                    <table className="table table-hover">
                                        <thead className="table-light">
                                            <tr>
                                                <th>Date & Time</th>
                                                <th>IP Address</th>
                                                <th>Device</th>
                                                <th>Browser</th>
                                                <th>Status</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr>
                                                <td>{new Date(userData.login_history.login_date).toLocaleString()}</td>
                                                <td>{formatIpAddress(userData.login_history.ip_address)}</td>
                                                <td>{getDeviceInfo(userData.login_history.user_agent)}</td>
                                                <td>{getBrowserInfo(userData.login_history.user_agent)}</td>
                                                <td>
                                                    <span className="badge bg-success">Success</span>
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {/* Settings Panel */}
            <div className={`settings-panel bg-white shadow-lg ${isSettingsOpen ? 'open' : ''}`}>
                <div className="settings-header">
                    <h3 className="mb-0">Settings</h3>
                    <button className="btn btn-link text-muted p-0" onClick={toggleSettings}>
                        <i className="fas fa-times"></i>
                    </button>
                </div>
                <div className="settings-content">
                    <div className="settings-section">
                        <h4 className="mb-3">Display Settings</h4>
                        <div className="form-check form-switch">
                            <input className="form-check-input" type="checkbox" id="darkMode" />
                            <label className="form-check-label" htmlFor="darkMode">Dark Mode</label>
                        </div>
                    </div>
                    <div className="settings-section">
                        <h4 className="mb-3">Notifications</h4>
                        <div className="form-check form-switch">
                            <input className="form-check-input" type="checkbox" id="emailNotifications" />
                            <label className="form-check-label" htmlFor="emailNotifications">Email Notifications</label>
                        </div>
                    </div>
                </div>
            </div>

            {/* Logout Confirmation Modal */}
            {showLogoutConfirm && (
                <LogoutConfirmationModal
                    onClose={handleLogoutCancel}
                    onConfirm={handleLogoutConfirm}
                />
            )}

            {/* Profile Update Modal */}
            <ProfileUpdateModal
                show={showProfileUpdateModal}
                onClose={handleProfileUpdateClose}
                onUpdate={handleProfileUpdateSuccess}
                currentUser={userData}
            />
        </div>
    );
};

export default UserDashboard; 