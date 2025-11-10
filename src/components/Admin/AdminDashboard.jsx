import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';
import './AdminDashboard.css';
import 'bootstrap/dist/css/bootstrap.min.css';
import '@fortawesome/fontawesome-free/css/all.min.css';
import UserDetailsModal from './UserDetailsModal';
import AddUserModal from './AddUserModal';
import BlockedUsersModal from './BlockedUsersModal';
import ChangePasswordModal from './ChangePasswordModal';
import LogoutConfirmationModal from '../Common/LogoutConfirmationModal';
import AdminPasswordModal from './AdminPasswordModal';
import AuditLog from './AuditLog';
import axios from 'axios';

const getBrowserInfo = (userAgent) => {
    if (!userAgent) return 'Unknown';
    if (userAgent.includes('Chrome')) return 'Chrome';
    if (userAgent.includes('Firefox')) return 'Firefox';
    if (userAgent.includes('Safari')) return 'Safari';
    if (userAgent.includes('Edge')) return 'Edge';
    if (userAgent.includes('MSIE') || userAgent.includes('Trident/')) return 'Internet Explorer';
    return 'Other Browser';
};

const getBrowserIcon = (userAgent) => {
    if (!userAgent) return 'question-circle';
    if (userAgent.includes('Chrome')) return 'chrome';
    if (userAgent.includes('Firefox')) return 'firefox';
    if (userAgent.includes('Safari')) return 'safari';
    if (userAgent.includes('Edge')) return 'edge';
    if (userAgent.includes('MSIE') || userAgent.includes('Trident/')) return 'internet-explorer';
    return 'globe';
};

const getDeviceInfo = (userAgent) => {
    if (!userAgent) return 'Unknown';
    if (userAgent.includes('Mobile')) return 'Mobile';
    if (userAgent.includes('Tablet')) return 'Tablet';
    if (userAgent.includes('Windows')) return 'Windows PC';
    if (userAgent.includes('Mac')) return 'Mac';
    if (userAgent.includes('Linux')) return 'Linux PC';
    return 'Desktop';
};

const getDeviceIcon = (userAgent) => {
    if (!userAgent) return 'question-circle';
    if (userAgent.includes('Mobile')) return 'mobile-alt';
    if (userAgent.includes('Tablet')) return 'tablet-alt';
    return 'desktop';
};

const formatIpAddress = (ip) => {
    if (!ip) return 'N/A';
    // Convert IPv6 localhost to IPv4 localhost
    if (ip === '::1') return '127.0.0.1';
    return ip;
};

const AdminDashboard = () => {
    const navigate = useNavigate();
    const [adminData, setAdminData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [activeTab, setActiveTab] = useState('overview');
    const [loginHistory, setLoginHistory] = useState([]);
    const [loadingHistory, setLoadingHistory] = useState(false);
    const [userStats, setUserStats] = useState(null);
    const [users, setUsers] = useState([]);
    const [selectedUser, setSelectedUser] = useState(null);
    const [userDetails, setUserDetails] = useState(null);
    const [loadingUserDetails, setLoadingUserDetails] = useState(false);
    const [showUserDetails, setShowUserDetails] = useState(false);
    const [showAddUser, setShowAddUser] = useState(false);
    const [showLogoutConfirm, setShowLogoutConfirm] = useState(false);
    const [showBlockedUsers, setShowBlockedUsers] = useState(false);
    const [showChangePassword, setShowChangePassword] = useState(false);
    const [showLoginHistory, setShowLoginHistory] = useState(false);
    const [showAuditLog, setShowAuditLog] = useState(false);
    const [showNotificationSettings, setShowNotificationSettings] = useState(false);
    const [showSecuritySettings, setShowSecuritySettings] = useState(false);
    const [showSystemSettings, setShowSystemSettings] = useState(false);
    const [notificationSettings, setNotificationSettings] = useState({
        email: true,
        system: true
    });
    const [securitySettings, setSecuritySettings] = useState({
        maxLoginAttempts: 3,
        lockoutDuration: 15
    });
    const [systemSettings, setSystemSettings] = useState({
        sessionTimeout: 30,
        language: 'en'
    });
    const [stats, setStats] = useState({
        totalUsers: 0,
        blockedUsers: 0,
        activeSessions: 0,
        todayRegistrations: 0
    });
    const [recentActivity, setRecentActivity] = useState([]);
    const [systemStatus, setSystemStatus] = useState({
        database: true,
        api: true,
        email: true,
        storage: true
    });
    const [showRoleConfirm, setShowRoleConfirm] = useState(false);
    const [roleChangeUser, setRoleChangeUser] = useState(null);
    const [showAdminPasswordModal, setShowAdminPasswordModal] = useState(false);
    const [pendingAction, setPendingAction] = useState(null);
    const [pendingUserData, setPendingUserData] = useState(null);
    const [currentPage, setCurrentPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [totalUsers, setTotalUsers] = useState(0);
    const [usersPerPage, setUsersPerPage] = useState(8);
    const [paginationInfo, setPaginationInfo] = useState(null);

    useEffect(() => {
        const token = localStorage.getItem('adminToken');
        if (!token) {
            navigate('/admin-login-55x');
            return;
        }

        fetchAdminData();
        fetchUserStats();
        fetchUsers(1, usersPerPage);
        fetchDashboardData();
    }, [navigate]);

    const fetchAdminData = async () => {
        try {
            const response = await api.getAdminProfile();
            if (response.error) {
                setError(response.error);
            } else {
                setAdminData(response.admin);
            }
        } catch (error) {
            setError('Failed to fetch admin data');
        } finally {
            setLoading(false);
        }
    };

    const fetchUserStats = async () => {
        try {
            const response = await api.getUserStatistics();
            if (response.error) {
                setError(response.error);
            } else {
                setUserStats(response.statistics);
            }
        } catch (error) {
            setError('Failed to fetch user statistics');
        }
    };

    const fetchUsers = async (page = currentPage, limit = usersPerPage) => {
        try {
            const response = await api.getAllUsers(page, limit);
            if (response.error) {
                setError(response.error);
            } else {
                setUsers(response.users);
                setPaginationInfo(response.pagination);
                setCurrentPage(response.pagination.currentPage);
                setTotalPages(response.pagination.totalPages);
                setTotalUsers(response.pagination.totalUsers);
            }
        } catch (error) {
            setError('Failed to fetch users');
        }
    };

    const handlePageChange = (newPage) => {
        if (newPage >= 1 && newPage <= totalPages) {
            setCurrentPage(newPage);
            fetchUsers(newPage, usersPerPage);
        }
    };

    const handleUsersPerPageChange = (newLimit) => {
        setUsersPerPage(newLimit);
        setCurrentPage(1); // Reset to first page when changing limit
        fetchUsers(1, newLimit);
    };

    const fetchUserDetails = async (userId) => {
        setLoadingUserDetails(true);
        try {
            const response = await api.getUserDetails(userId);
            if (response.error) {
                setError(response.error);
            } else {
                setUserDetails(response);
            }
        } catch (error) {
            setError('Failed to fetch user details');
        } finally {
            setLoadingUserDetails(false);
        }
    };

    const handleUserSelect = (user) => {
        setSelectedUser(user);
        fetchUserDetails(user.id);
        setShowUserDetails(true);
    };

    const handleCloseUserDetails = () => {
        setShowUserDetails(false);
        setSelectedUser(null);
        setUserDetails(null);
    };

    const handleDeleteUser = async (userId) => {
        try {
            const response = await api.deleteUser(userId);
            if (response.error) {
                throw new Error(response.error);
            }
            // Refresh the users list on current page
            fetchUsers(currentPage, usersPerPage);
            // Refresh user statistics
            fetchUserStats();
        } catch (error) {
            throw new Error('Failed to delete user');
        }
    };

    const handleAddUser = async (userData) => {
        try {
            const response = await api.addUser(userData);
            if (response.error) {
                throw new Error(response.error);
            }
            // Refresh the users list on current page
            fetchUsers(currentPage, usersPerPage);
            // Refresh user statistics
            fetchUserStats();
        } catch (error) {
            throw new Error('Failed to add user');
        }
    };

    const handleLogout = () => {
        setShowLogoutConfirm(true);
    };

    const handleLogoutConfirm = () => {
        localStorage.removeItem('adminToken');
        navigate('http://localhost:5173/');
    };

    const handleLogoutCancel = () => {
        setShowLogoutConfirm(false);
    };

    const fetchLoginHistory = async () => {
        setLoadingHistory(true);
        try {
            const response = await api.getAdminLoginHistory();
            if (response.error) {
                setError(response.error);
            } else {
                setLoginHistory(response.loginHistory);
            }
        } catch (error) {
            setError('Failed to fetch login history');
        } finally {
            setLoadingHistory(false);
        }
    };

    useEffect(() => {
        if (activeTab === 'security') {
            fetchLoginHistory();
        }
    }, [activeTab]);

    const handleUnblockUser = () => {
        // Refresh user statistics after unblocking
        fetchUserStats();
    };

    const fetchDashboardData = async () => {
        try {
            const response = await api.getUserStatistics();
            if (response.error) {
                setError(response.error);
            } else {
                setStats({
                    totalUsers: response.statistics.totalUsers || 0,
                    blockedUsers: response.statistics.blockedUsers || 0,
                    activeSessions: response.statistics.activeSessions || 0,
                    todayRegistrations: response.statistics.todayRegistrations || 0
                });
            }

            // Fetch recent audit logs
            const auditResponse = await axios.get('http://localhost:5000/api/admin/audit-logs', {
                params: {
                    page: 1,
                    limit: 3
                },
                headers: {
                    Authorization: `Bearer ${localStorage.getItem('adminToken')}`
                }
            });

            if (auditResponse.data && Array.isArray(auditResponse.data.logs)) {
                const formattedActivity = auditResponse.data.logs.map(log => ({
                    timestamp: new Date(log.event_time),
                    user: log.actor_username,
                    action: log.action,
                    status: log.metadata?.status || (log.description.toLowerCase().includes('failed') ? 'failed' : 'success')
                }));
                setRecentActivity(formattedActivity);
            }

            setSystemStatus({
                database: true,
                api: true,
                email: true,
                storage: true
            });
        } catch (error) {
            console.error('Error fetching dashboard data:', error);
            setError('Failed to fetch dashboard data');
        }
    };

    const handleViewLogs = () => {
        navigate('/admin/audit-logs');
    };

    const handleRoleChange = (user) => {
        setRoleChangeUser(user);
        setShowAdminPasswordModal(true);
        setPendingAction('roleChange');
    };

    const handleAddUserWithRole = (userData) => {
        if (userData.role === 'admin') {
            setPendingAction('addUser');
            setShowAdminPasswordModal(true);
            setPendingUserData(userData);
        } else {
            handleAddUser(userData);
        }
    };

    const handleAdminPasswordVerify = async (password) => {
        try {
            const response = await api.verifyAdminPassword(password);
            if (response.error) {
                throw new Error(response.error);
            }

            if (pendingAction === 'roleChange') {
                setShowAdminPasswordModal(false);
                setShowRoleConfirm(true);
            } else if (pendingAction === 'addUser') {
                setShowAdminPasswordModal(false);
                handleAddUser(pendingUserData);
            }
        } catch (error) {
            throw new Error('Invalid admin password');
        }
    };

    const handleRoleConfirm = async () => {
        try {
            const newRole = roleChangeUser.role === 'admin' ? 'user' : 'admin';
            const response = await api.updateUserRole(roleChangeUser.id, newRole);
            if (response.error) {
                throw new Error(response.error);
            }
            // Refresh the users list on current page
            fetchUsers(currentPage, usersPerPage);
            setShowRoleConfirm(false);
            setRoleChangeUser(null);
        } catch (error) {
            setError('Failed to update user role');
            setShowRoleConfirm(false);
            setRoleChangeUser(null);
        }
    };

    const handleRoleCancel = () => {
        setShowRoleConfirm(false);
        setRoleChangeUser(null);
    };

    const renderUsersTab = () => (
        <div className="users-tab">
            <div className="d-flex justify-content-between align-items-center mb-4">
                <h2>User Management</h2>
                <div className="d-flex gap-2">
                    <button className="btn btn-primary" onClick={() => setShowAddUser(true)}>
                        <i className="fas fa-user-plus me-2"></i>Add New User
                    </button>
                    <button className="btn btn-warning" onClick={() => setShowBlockedUsers(true)}>
                        <i className="fas fa-user-lock me-2"></i>Block Account
                    </button>
                </div>
            </div>

            <div className="table-responsive">
                <table className="table table-hover">
                    <thead>
                        <tr>
                            <th className="text-center">Username</th>
                            <th className="text-center">Email</th>
                            <th className="text-center">Role</th>
                            <th className="text-center">Registration Method</th>
                            <th className="text-center">Account Created</th>
                            <th className="text-center">Email Status</th>
                            <th className="text-center">Last Login</th>
                            <th className="text-center">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users.map(user => (
                            <tr key={user.id}>
                                <td className="text-center">{user.username}</td>
                                <td className="text-center">{user.email}</td>
                                <td className="text-center">
                                    <span className={`badge ${user.role === 'admin' ? 'bg-danger' : 'bg-primary'}`}>
                                        {user.role ? user.role.charAt(0).toUpperCase() + user.role.slice(1) : 'User'}
                                    </span>
                                </td>
                                <td className="text-center text-capitalize">
                                    {user.registerMethod ? user.registerMethod.charAt(0).toUpperCase() + user.registerMethod.slice(1) : 'Manual'}
                                </td>
                                <td className="text-center">{user.createdAt ? new Date(user.createdAt).toLocaleString() : 'N/A'}</td>
                                <td className="text-center">
                                    <span className={`badge ${user.emailVerified ? 'bg-success' : 'bg-warning text-dark'}`}>
                                        {user.emailVerified ? 'Verified' : 'Not Verified'}
                                    </span>
                                </td>
                                <td className="text-center">{user.lastLogin == null || user.loginCount === 0 ? 'Never' : new Date(user.lastLogin).toLocaleString()}</td>
                                <td className="text-center">
                                <div className="btn-group d-flex justify-content-center">
    <button
        className="btn btn-outline-primary btn-sm me-2 py-1 px-2 small"
        onClick={() => handleUserSelect(user)}
    >
        <i className="fas fa-eye me-1"></i> View
    </button>

    {user.role !== 'admin' ? (
        <button
            className="btn btn-outline-success btn-sm py-1 px-1 small"
            onClick={() => handleRoleChange(user)}
            style={{ width: '120px' }}
        >
            <i className="fas fa-user-shield me-1"></i> Make Admin
        </button>
    ) : (
        <button
            className="btn btn-outline-warning btn-sm py-1 px-2 small"
            onClick={() => handleRoleChange(user)}
            style={{ width: '120px' }}
        >
            <i className="fas fa-user me-1"></i> Make User
        </button>
    )}
</div>

                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {/* Pagination */}
            {paginationInfo && (
                <div className="pagination-container mt-4">
                    <div className="row align-items-center">
                        <div className="col-md-6">
                            <div className="d-flex align-items-center">
                                <span className="me-3">Show:</span>
                                <select 
                                    className="form-select form-select-sm me-3" 
                                    style={{ width: 'auto' }}
                                    value={usersPerPage}
                                    onChange={(e) => handleUsersPerPageChange(parseInt(e.target.value))}
                                >
                                    <option value={5}>5</option>
                                    <option value={8}>8</option>
                                    <option value={10}>10</option>
                                    <option value={20}>20</option>
                                    <option value={50}>50</option>
                                </select>
                                <span className="text-muted">
                                    of {totalUsers} users
                                </span>
                            </div>
                        </div>
                        <div className="col-md-6">
                            <div className="d-flex justify-content-end align-items-center">
                                <span className="me-3">
                                    Page {currentPage} of {totalPages}
                                </span>
                                <nav aria-label="User pagination">
                                    <ul className="pagination pagination-sm mb-0">
                                        {/* Show Previous button only if not on first page */}
                                        {currentPage > 1 && (
                                            <li className="page-item">
                                                <button 
                                                    className="page-link" 
                                                    onClick={() => handlePageChange(currentPage - 1)}
                                                >
                                                    Previous
                                                </button>
                                            </li>
                                        )}
                                        
                                        {/* Page numbers */}
                                        {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                                            let pageNum;
                                            if (totalPages <= 5) {
                                                pageNum = i + 1;
                                            } else if (currentPage <= 3) {
                                                pageNum = i + 1;
                                            } else if (currentPage >= totalPages - 2) {
                                                pageNum = totalPages - 4 + i;
                                            } else {
                                                pageNum = currentPage - 2 + i;
                                            }
                                            
                                            return (
                                                <li key={pageNum} className={`page-item ${currentPage === pageNum ? 'active' : ''}`}>
                                                    <button 
                                                        className="page-link" 
                                                        onClick={() => handlePageChange(pageNum)}
                                                    >
                                                        {pageNum}
                                                    </button>
                                                </li>
                                            );
                                        })}
                                        
                                        {/* Show Next button only if not on last page */}
                                        {currentPage < totalPages && (
                                            <li className="page-item">
                                                <button 
                                                    className="page-link" 
                                                    onClick={() => handlePageChange(currentPage + 1)}
                                                >
                                                    Next
                                                </button>
                                            </li>
                                        )}
                                    </ul>
                                </nav>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Role Change Confirmation Modal */}
            {showRoleConfirm && roleChangeUser && (
                <div className="modal-overlay" onClick={handleRoleCancel}>
                    <div className="modal-content" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>Confirm Role Change</h3>
                            <button className="close-button" onClick={handleRoleCancel}>
                                <i className="fas fa-times"></i>
                            </button>
                        </div>
                        <div className="modal-body">
                            <p>Are you sure you want to change {roleChangeUser.username}'s role from {roleChangeUser.role} to {roleChangeUser.role === 'admin' ? 'user' : 'admin'}?</p>
                            <div className="d-flex justify-content-end gap-2 mt-4">
                                <button className="btn btn-secondary" onClick={handleRoleCancel}>
                                    Cancel
                                </button>
                                <button className="btn btn-primary" onClick={handleRoleConfirm}>
                                    Confirm Change
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Existing modals */}
            {showUserDetails && selectedUser && (
                <UserDetailsModal
                    user={userDetails?.user}
                    onClose={handleCloseUserDetails}
                    onDeleteUser={handleDeleteUser}
                />
            )}
            {showAddUser && (
                <AddUserModal
                    onClose={() => setShowAddUser(false)}
                    onAddUser={handleAddUserWithRole}
                />
            )}
            {showAdminPasswordModal && (
                <AdminPasswordModal
                    onClose={() => {
                        setShowAdminPasswordModal(false);
                        setPendingAction(null);
                        setPendingUserData(null);
                    }}
                    onVerify={handleAdminPasswordVerify}
                    title={pendingAction === 'roleChange' ? 'Verify Admin Password for Role Change' : 'Verify Admin Password for Adding Admin User'}
                />
            )}
        </div>
    );

    const renderSecurityTab = () => (
        <div className="security-section container py-4">
            <div className="row g-4">
                <div className="col-md-4">
                    <div className="card h-100">
                        <div className="card-body text-center">
                            <i className="fas fa-history fa-3x mb-3 text-primary"></i>
                            <h5 className="card-title">Login History</h5>
                            <p className="card-text">View your recent login activities and sessions</p>
                            <button
                                className="btn btn-primary"
                                onClick={() => setShowLoginHistory(true)}
                            >
                                View History
                            </button>
                        </div>
                    </div>
                </div>
                <div className="col-md-4">
                    <div className="card h-100">
                        <div className="card-body text-center">
                            <i className="fas fa-key fa-3x mb-3 text-warning"></i>
                            <h5 className="card-title">Change Password</h5>
                            <p className="card-text">Update your admin account password</p>
                            <button
                                className="btn btn-warning"
                                onClick={() => setShowChangePassword(true)}
                            >
                                Change Password
                            </button>
                        </div>
                    </div>
                </div>
                <div className="col-md-4">
                    <div className="card h-100">
                        <div className="card-body text-center">
                            <i className="fas fa-clipboard-list fa-3x mb-3 text-info"></i>
                            <h5 className="card-title">Audit Log</h5>
                            <p className="card-text">View system activity and security logs</p>
                            <button
                                className="btn btn-info text-white"
                                onClick={handleViewLogs}
                            >
                                View Logs
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            {/* Login History Modal */}
            {showLoginHistory && (
                <div className="modal-overlay">
                    <div className="modal-content login-history-modal" style={{ width: '80%', maxWidth: '800px' }}>
                        <div className="modal-header">
                            <h3><i className="fas fa-history me-2"></i>Login History</h3>
                            <button className="close-button" onClick={() => setShowLoginHistory(false)}>
                                <i className="fas fa-times"></i>
                            </button>
                        </div>
                        <div className="modal-body">
                            {loadingHistory ? (
                                <div className="text-center">
                                    <div className="spinner-border text-primary" role="status">
                                        <span className="visually-hidden">Loading...</span>
                                    </div>
                                </div>
                            ) : error ? (
                                <div className="alert alert-danger">{error}</div>
                            ) : loginHistory.length === 0 ? (
                                <div className="text-center">
                                    <p>No login history found</p>
                                </div>
                            ) : (
                                <div className="table-responsive">
                                    <table className="table table-hover">
                                        <thead className="table-light">
                                            <tr>
                                                <th>Login Date & Time</th>
                                                <th>IP Address</th>
                                                <th>Browser</th>
                                                <th>Device</th>
                                                <th>Login Count</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {loginHistory.map((login, index) => (
                                                <tr key={index}>
                                                    <td>
                                                        {new Date(login.login_time).toLocaleString('en-US', {
                                                            year: 'numeric',
                                                            month: 'short',
                                                            day: 'numeric',
                                                            hour: '2-digit',
                                                            minute: '2-digit',
                                                            second: '2-digit',
                                                            hour12: true
                                                        })}
                                                    </td>
                                                    <td>
                                                        <span className="badge bg-info">
                                                            {formatIpAddress(login.ip_address)}
                                                        </span>
                                                    </td>
                                                    <td>
                                                        {login.user_agent ? (
                                                            <div>
                                                                <i className={`fab fa-${getBrowserIcon(login.user_agent)} me-2`}></i>
                                                                {getBrowserInfo(login.user_agent)}
                                                            </div>
                                                        ) : 'N/A'}
                                                    </td>
                                                    <td>
                                                        {login.user_agent ? (
                                                            <div>
                                                                <i className={`fas fa-${getDeviceIcon(login.user_agent)} me-2`}></i>
                                                                {getDeviceInfo(login.user_agent)}
                                                            </div>
                                                        ) : 'N/A'}
                                                    </td>
                                                    <td>
                                                        <span className="badge bg-secondary">
                                                            {login.login_count || 0}
                                                        </span>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Audit Log Modal */}
            {showAuditLog && (
                <AuditLog onClose={() => setShowAuditLog(false)} />
            )}
        </div>
    );

    const renderSettingsTab = () => (
        <div className="settings-section container py-4">
            <div className="row g-4">
                <div className="col-md-4">
                    <div className="card h-100">
                        <div className="card-body text-center">
                            <i className="fas fa-bell fa-3x mb-3 text-primary"></i>
                            <h5 className="card-title">Notification Settings</h5>
                            <p className="card-text">Configure email and system notifications</p>
                            <button
                                className="btn btn-primary"
                                onClick={() => setShowNotificationSettings(true)}
                            >
                                Configure
                            </button>
                        </div>
                    </div>
                </div>
                <div className="col-md-4">
                    <div className="card h-100">
                        <div className="card-body text-center">
                            <i className="fas fa-shield-alt fa-3x mb-3 text-warning"></i>
                            <h5 className="card-title">Security Settings</h5>
                            <p className="card-text">Manage security policies and restrictions</p>
                            <button
                                className="btn btn-warning"
                                onClick={() => setShowSecuritySettings(true)}
                            >
                                Manage
                            </button>
                        </div>
                    </div>
                </div>
                <div className="col-md-4">
                    <div className="card h-100">
                        <div className="card-body text-center">
                            <i className="fas fa-cog fa-3x mb-3 text-info"></i>
                            <h5 className="card-title">System Settings</h5>
                            <p className="card-text">Configure system preferences and defaults</p>
                            <button
                                className="btn btn-info text-white"
                                onClick={() => setShowSystemSettings(true)}
                            >
                                Configure
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            {/* Notification Settings Modal */}
            {showNotificationSettings && (
                <div className="modal-overlay">
                    <div className="modal-content settings-modal">
                        <div className="modal-header">
                            <h3>Notification Settings</h3>
                            <button className="close-button" onClick={() => setShowNotificationSettings(false)}>
                                <i className="fas fa-times"></i>
                            </button>
                        </div>
                        <div className="modal-body">
                            <form onSubmit={handleNotificationSettingsSubmit}>
                                <div className="mb-3">
                                    <div className="form-check form-switch">
                                        <input
                                            className="form-check-input"
                                            type="checkbox"
                                            id="emailNotifications"
                                            checked={notificationSettings.email}
                                            onChange={(e) => setNotificationSettings(prev => ({
                                                ...prev,
                                                email: e.target.checked
                                            }))}
                                        />
                                        <label className="form-check-label" htmlFor="emailNotifications">
                                            Email Notifications
                                        </label>
                                    </div>
                                </div>
                                <div className="mb-3">
                                    <div className="form-check form-switch">
                                        <input
                                            className="form-check-input"
                                            type="checkbox"
                                            id="systemNotifications"
                                            checked={notificationSettings.system}
                                            onChange={(e) => setNotificationSettings(prev => ({
                                                ...prev,
                                                system: e.target.checked
                                            }))}
                                        />
                                        <label className="form-check-label" htmlFor="systemNotifications">
                                            System Notifications
                                        </label>
                                    </div>
                                </div>
                                <div className="d-grid gap-2">
                                    <button type="submit" className="btn btn-primary">
                                        Save Changes
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            )}

            {/* Security Settings Modal */}
            {showSecuritySettings && (
                <div className="modal-overlay">
                    <div className="modal-content settings-modal">
                        <div className="modal-header">
                            <h3>Security Settings</h3>
                            <button className="close-button" onClick={() => setShowSecuritySettings(false)}>
                                <i className="fas fa-times"></i>
                            </button>
                        </div>
                        <div className="modal-body">
                            <form onSubmit={handleSecuritySettingsSubmit}>
                                <div className="mb-3">
                                    <label className="form-label">Failed Login Attempts</label>
                                    <input
                                        type="number"
                                        className="form-control"
                                        value={securitySettings.maxLoginAttempts}
                                        onChange={(e) => setSecuritySettings(prev => ({
                                            ...prev,
                                            maxLoginAttempts: parseInt(e.target.value)
                                        }))}
                                        min="1"
                                        max="10"
                                    />
                                    <small className="text-muted">Number of failed attempts before account lockout</small>
                                </div>
                                <div className="mb-3">
                                    <label className="form-label">Lockout Duration (minutes)</label>
                                    <input
                                        type="number"
                                        className="form-control"
                                        value={securitySettings.lockoutDuration}
                                        onChange={(e) => setSecuritySettings(prev => ({
                                            ...prev,
                                            lockoutDuration: parseInt(e.target.value)
                                        }))}
                                        min="5"
                                        max="60"
                                    />
                                </div>
                                <div className="d-grid gap-2">
                                    <button type="submit" className="btn btn-primary">
                                        Save Changes
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            )}

            {/* System Settings Modal */}
            {showSystemSettings && (
                <div className="modal-overlay">
                    <div className="modal-content settings-modal">
                        <div className="modal-header">
                            <h3>System Settings</h3>
                            <button className="close-button" onClick={() => setShowSystemSettings(false)}>
                                <i className="fas fa-times"></i>
                            </button>
                        </div>
                        <div className="modal-body">
                            <form onSubmit={handleSystemSettingsSubmit}>
                                <div className="mb-3">
                                    <label className="form-label">Session Timeout (minutes)</label>
                                    <input
                                        type="number"
                                        className="form-control"
                                        value={systemSettings.sessionTimeout}
                                        onChange={(e) => setSystemSettings(prev => ({
                                            ...prev,
                                            sessionTimeout: parseInt(e.target.value)
                                        }))}
                                        min="5"
                                        max="120"
                                    />
                                </div>
                                <div className="mb-3">
                                    <label className="form-label">Default Language</label>
                                    <select
                                        className="form-select"
                                        value={systemSettings.language}
                                        onChange={(e) => setSystemSettings(prev => ({
                                            ...prev,
                                            language: e.target.value
                                        }))}
                                    >
                                        <option value="en">English</option>
                                        <option value="es">Spanish</option>
                                        <option value="fr">French</option>
                                    </select>
                                </div>
                                <div className="d-grid gap-2">
                                    <button type="submit" className="btn btn-primary">
                                        Save Changes
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );

    const handleNotificationSettingsSubmit = async (e) => {
        e.preventDefault();
        try {
            await api.post('/admin/settings/notifications', notificationSettings);
            // Show success message
        } catch (error) {
            // Show error message
        }
    };

    const handleSecuritySettingsSubmit = async (e) => {
        e.preventDefault();
        try {
            await api.post('/admin/settings/security', securitySettings);
            // Show success message
        } catch (error) {
            // Show error message
        }
    };

    const handleSystemSettingsSubmit = async (e) => {
        e.preventDefault();
        try {
            await api.post('/admin/settings/system', systemSettings);
            // Show success message
        } catch (error) {
            // Show error message
        }
    };

    const renderOverviewTab = () => (
        <div className="overview-section container py-4">
            {/* Statistics Cards Row */}
            <div className="row g-4 mb-4">
                <div className="col-md-3">
                    <div className="card h-100">
                        <div className="card-body text-center">
                            <i className="fas fa-users fa-3x mb-3 text-primary"></i>
                            <h5 className="card-title">Total Users</h5>
                            <h2 className="display-4 mb-0">{stats.totalUsers}</h2>
                            <p className="text-muted small">Active accounts</p>
                        </div>
                    </div>
                </div>
                <div className="col-md-3">
                    <div className="card h-100">
                        <div className="card-body text-center">
                            <i className="fas fa-user-lock fa-3x mb-3 text-warning"></i>
                            <h5 className="card-title">Blocked Users</h5>
                            <h2 className="display-4 mb-0">{stats.blockedUsers}</h2>
                            <p className="text-muted small">Currently blocked</p>
                        </div>
                    </div>
                </div>
                <div className="col-md-3">
                    <div className="card h-100">
                        <div className="card-body text-center">
                            <i className="fas fa-sign-in-alt fa-3x mb-3 text-success"></i>
                            <h5 className="card-title">Active Sessions</h5>
                            <h2 className="display-4 mb-0">{stats.activeSessions}</h2>
                            <p className="text-muted small">Current logins</p>
                        </div>
                    </div>
                </div>
                <div className="col-md-3">
                    <div className="card h-100">
                        <div className="card-body text-center">
                            <i className="fas fa-user-plus fa-3x mb-3 text-info"></i>
                            <h5 className="card-title">Today's Registrations</h5>
                            <h2 className="display-4 mb-0">{stats.todayRegistrations}</h2>
                            <p className="text-muted small">New accounts today</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Recent Activity and System Status Row */}
            <div className="row g-4">
                <div className="col-md-8">
                    <div className="card h-100">
                        <div className="card-header bg-white">
                            <h5 className="card-title mb-0">
                                <i className="fas fa-history me-2"></i>
                                Recent Activity
                            </h5>
                        </div>
                        <div className="card-body">
                            <div className="table-responsive">
                                <table className="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>Time</th>
                                            <th>User</th>
                                            <th>Action</th>
                                            <th>Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {recentActivity.slice(0, 3).map((activity, index) => (
                                            <tr key={index}>
                                                <td>{new Date(activity.timestamp).toLocaleString()}</td>
                                                <td>{activity.user}</td>
                                                <td>{activity.action}</td>
                                                <td>
                                                    <span className={`badge bg-${activity.status === 'success' ? 'success' : 'danger'}`}>
                                                        {activity.status}
                                                    </span>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                <div className="col-md-4">
                    <div className="card h-100">
                        <div className="card-header bg-white">
                            <h5 className="card-title mb-0">
                                <i className="fas fa-server me-2"></i>
                                System Status
                            </h5>
                        </div>
                        <div className="card-body">
                            <div className="system-status">
                                <div className="status-item mb-3">
                                    <div className="d-flex justify-content-between align-items-center">
                                        <span>Database</span>
                                        <span className={`badge bg-${systemStatus.database ? 'success' : 'danger'}`}>
                                            {systemStatus.database ? 'Online' : 'Offline'}
                                        </span>
                                    </div>
                                </div>
                                <div className="status-item mb-3">
                                    <div className="d-flex justify-content-between align-items-center">
                                        <span>API Server</span>
                                        <span className={`badge bg-${systemStatus.api ? 'success' : 'danger'}`}>
                                            {systemStatus.api ? 'Online' : 'Offline'}
                                        </span>
                                    </div>
                                </div>
                                <div className="status-item mb-3">
                                    <div className="d-flex justify-content-between align-items-center">
                                        <span>Email Service</span>
                                        <span className={`badge bg-${systemStatus.email ? 'success' : 'danger'}`}>
                                            {systemStatus.email ? 'Online' : 'Offline'}
                                        </span>
                                    </div>
                                </div>
                                <div className="status-item">
                                    <div className="d-flex justify-content-between align-items-center">
                                        <span>Storage</span>
                                        <span className={`badge bg-${systemStatus.storage ? 'success' : 'danger'}`}>
                                            {systemStatus.storage ? 'Online' : 'Offline'}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );

    if (loading) {
        return (
            <div className="admin-loading">
                <div className="spinner-border text-primary" role="status">
                    <span className="visually-hidden">Loading...</span>
                </div>
                <p className="mt-3">Loading admin dashboard...</p>
            </div>
        );
    }

    if (error) {
        return (
            <div className="admin-error">
                <div className="alert alert-danger" role="alert">
                    {error}
                </div>
            </div>
        );
    }

    return (
        <div className="admin-dashboard">
            <div className="admin-sidebar">
                <div className="sidebar-header">
                    <h3>Admin Panel</h3>
                </div>
                <div className="admin-info">
                    <div className="admin-avatar">
                        <i className="fas fa-user-shield"></i>
                    </div>
                    <div className="admin-details">
                        <h4>{adminData.username}</h4>
                        <p>{adminData.email}</p>
                        <span className="admin-role">Administrator</span>
                    </div>
                </div>
                <nav className="sidebar-nav">
                    <button
                        className={`nav-button ${activeTab === 'overview' ? 'active' : ''}`}
                        onClick={() => setActiveTab('overview')}
                    >
                        <i className="fas fa-chart-line"></i>
                        Overview
                    </button>
                    <button
                        className={`nav-button ${activeTab === 'users' ? 'active' : ''}`}
                        onClick={() => setActiveTab('users')}
                    >
                        <i className="fas fa-users"></i>
                        Users
                    </button>
                    <button
                        className={`nav-button ${activeTab === 'security' ? 'active' : ''}`}
                        onClick={() => setActiveTab('security')}
                    >
                        <i className="fas fa-shield-alt"></i>
                        Security
                    </button>
                    <button
                        className={`nav-button ${activeTab === 'settings' ? 'active' : ''}`}
                        onClick={() => setActiveTab('settings')}
                    >
                        <i className="fas fa-cog"></i>
                        Settings
                    </button>
                </nav>
            </div>

            <div className="admin-main">
                <div className="admin-header">
                    <button className="logout-button" onClick={handleLogout}>
                        <i className="fas fa-sign-out-alt"></i>
                        Logout
                    </button>
                </div>

                <div className="admin-content">
                    {activeTab === 'overview' && renderOverviewTab()}
                    {activeTab === 'users' && renderUsersTab()}
                    {activeTab === 'security' && renderSecurityTab()}
                    {activeTab === 'settings' && renderSettingsTab()}
                </div>
            </div>

            {/* User Details Modal */}
            {showUserDetails && userDetails && (
                <UserDetailsModal
                    user={userDetails.user}
                    onClose={handleCloseUserDetails}
                    onDeleteUser={handleDeleteUser}
                />
            )}

            {/* Logout Confirmation Modal */}
            {showLogoutConfirm && (
                <LogoutConfirmationModal
                    onClose={handleLogoutCancel}
                    onConfirm={handleLogoutConfirm}
                />
            )}

            <BlockedUsersModal
                show={showBlockedUsers}
                onClose={() => setShowBlockedUsers(false)}
                onUnblock={handleUnblockUser}
            />

            <ChangePasswordModal
                show={showChangePassword}
                onClose={() => setShowChangePassword(false)}
            />
        </div>
    );
};

export default AdminDashboard;
