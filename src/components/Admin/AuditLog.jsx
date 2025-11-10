import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { format } from 'date-fns';
import { useNavigate } from 'react-router-dom';
import './AuditLog.css';

const AuditLog = () => {
    const navigate = useNavigate();
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [currentPage, setCurrentPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [logsPerPage, setLogsPerPage] = useState(7);
    const [totalLogs, setTotalLogs] = useState(0);
    const [paginationInfo, setPaginationInfo] = useState(null);
    const [filters, setFilters] = useState({
        actorType: '',
        action: '',
        startDate: '',
        endDate: ''
    });

    useEffect(() => {
        // Check if admin is logged in
        const adminToken = localStorage.getItem('adminToken');
        if (!adminToken) {
            navigate('/admin-login');
            return;
        }
        fetchLogs();
    }, [currentPage, logsPerPage, filters]);

    // Debug useEffect removed for cleaner output

    const fetchLogs = async () => {
        try {
            setLoading(true);
            const adminToken = localStorage.getItem('adminToken');
            if (!adminToken) {
                navigate('/admin-login');
                return;
            }

            const response = await axios.get('http://localhost:5000/api/admin/audit-logs', {
                params: {
                    page: currentPage,
                    limit: logsPerPage,
                    ...filters
                },
                headers: {
                    Authorization: `Bearer ${adminToken}`
                }
            });
            
            if (response.data && Array.isArray(response.data.logs)) {
                setLogs(response.data.logs);
                setTotalPages(response.data.totalPages || 1);
                setTotalLogs(response.data.totalLogs || 0);
                setPaginationInfo({
                    currentPage: response.data.currentPage || currentPage,
                    totalPages: response.data.totalPages || 1,
                    totalLogs: response.data.totalLogs || 0,
                    limit: logsPerPage
                });
            } else {
                console.error('Invalid response format:', response.data);
                setLogs([]);
                setTotalPages(1);
                setTotalLogs(0);
                setPaginationInfo(null);
            }
            setError(null);
        } catch (err) {
            console.error('Error fetching audit logs:', err.response || err);
            if (err.response?.status === 401) {
                // Token expired or invalid
                localStorage.removeItem('adminToken');
                navigate('/admin-login');
            } else {
                setError(err.response?.data?.error || 'Failed to fetch audit logs');
            }
            setLogs([]);
            setTotalPages(1);
            setTotalLogs(0);
            setPaginationInfo(null);
        } finally {
            setLoading(false);
        }
    };

    const handlePageChange = (newPage) => {
        if (newPage >= 1 && newPage <= totalPages) {
            setCurrentPage(newPage);
        }
    };

    const handleLogsPerPageChange = (newLimit) => {
        setLogsPerPage(newLimit);
        setCurrentPage(1); // Reset to first page when changing limit
    };

    const handleFilterChange = (e) => {
        const { name, value } = e.target;
        setFilters(prev => ({
            ...prev,
            [name]: value
        }));
        setCurrentPage(1);
    };

    const getActionColor = (action) => {
        const colors = {
            'login': 'success',
            'register': 'primary',
            'reset_password': 'warning',
            'admin_add_user': 'info',
            'admin_delete_user': 'danger',
            'password_change': 'warning',
            'profile_update': 'info',
            'role_change': 'secondary'
        };
        return colors[action] || 'secondary';
    };

    const formatMetadata = (metadata) => {
        try {
            const data = JSON.parse(metadata);
            if (data.old_role && data.new_role) {
                return `Role changed from ${data.old_role} to ${data.new_role}`;
            }
            return Object.entries(data)
                .map(([key, value]) => `${key}: ${value}`)
                .join(', ');
        } catch {
            return '';
        }
    };

    const formatIPAddress = (ip) => {
        if (!ip) {
            return 'N/A';
        }
        if (ip === '::1') {
            return '127.0.0.1';
        }
        // Remove IPv6 prefix if present
        return ip.replace(/^::ffff:/, '');
    };

    return (
        <div className="audit-log-page">
            <div className="container-fluid">
                <div className="header-section">
                    <div className="d-flex justify-content-between align-items-center">
                        <h2 className="mb-0">Audit Log</h2>
                        <button 
                            className="btn btn-warning"
                            onClick={() => navigate('/admin-dashboard')}
                        >
                            <i className="fas fa-arrow-left me-2"></i>
                            Back to Dashboard
                        </button>
                    </div>
                </div>

                <div className="filters-section">
                    <div className="row mb-4">
                        <div className="col-md-3">
                            <select
                                className="form-select"
                                name="actorType"
                                value={filters.actorType}
                                onChange={handleFilterChange}
                            >
                                <option value="">All Actor Types</option>
                                <option value="user">User</option>
                                <option value="admin">Admin</option>
                            </select>
                        </div>
                        <div className="col-md-3">
                            <select
                                className="form-select"
                                name="action"
                                value={filters.action}
                                onChange={handleFilterChange}
                            >
                                <option value="">All Actions</option>
                                <option value="login">Login</option>
                                <option value="register">Register</option>
                                <option value="reset_password">Reset Password</option>
                                <option value="admin_add_user">Add User</option>
                                <option value="admin_delete_user">Delete User</option>
                                <option value="password_change">Password Change</option>
                                <option value="profile_update">Profile Update</option>
                            </select>
                        </div>
                        <div className="col-md-3">
                            <input
                                type="date"
                                className="form-control"
                                name="startDate"
                                value={filters.startDate}
                                onChange={handleFilterChange}
                                placeholder="Start Date"
                            />
                        </div>
                        <div className="col-md-3">
                            <input
                                type="date"
                                className="form-control"
                                name="endDate"
                                value={filters.endDate}
                                onChange={handleFilterChange}
                                placeholder="End Date"
                            />
                        </div>
                    </div>
                </div>

                {error && (
                    <div className="alert alert-danger" role="alert">
                        {error}
                    </div>
                )}

                {loading ? (
                    <div className="text-center py-5">
                        <div className="spinner-border" role="status">
                            <span className="visually-hidden">Loading...</span>
                        </div>
                    </div>
                ) : logs.length === 0 ? (
                    <div className="text-center py-5">
                        <p className="text-muted">No audit logs found</p>
                    </div>
                ) : (
                    <div className="table-responsive">
                        <table className="table table-hover">
                            <thead className="table-light">
                                <tr>
                                    <th>Time</th>
                                    <th>Actor</th>
                                    <th>Type</th>
                                    <th>Action</th>
                                    <th>Target</th>
                                    <th>IP Address</th>
                                    <th>Description</th>
                                    
                                </tr>
                            </thead>
                            <tbody>
                                {logs.map((log) => (
                                    <tr key={log.id}>
                                        <td>{format(new Date(log.event_time), 'yyyy-MM-dd HH:mm:ss')}</td>
                                        <td>{log.actor_username}</td>
                                        <td>
                                            <span className={`badge bg-${log.actor_type === 'admin' ? 'danger' : 'primary'}`}>
                                                {log.actor_type}
                                            </span>
                                        </td>
                                        <td>
                                            <span className={`badge bg-${getActionColor(log.action)}`}>
                                                {log.action}
                                            </span>
                                        </td>
                                        <td>
                                            {log.target_username && (
                                                <div>
                                                    <div>{log.target_username}</div>
                                                    <small className="text-muted">{log.target_email}</small>
                                                </div>
                                            )}
                                        </td>
                                        <td>
                                            <span className="ip-address">
                                                {formatIPAddress(log.ip_address)}
                                            </span>
                                        </td>
                                        <td>{log.description}</td>
                                        <td>
                                            <small className="text-muted">
                                                {formatMetadata(log.metadata)}
                                            </small>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}

                {/* Pagination */}
                {logs.length > 0 && (
                    <div className="pagination-container mt-4">
                        <div className="row align-items-center">
                            <div className="col-md-6">
                                <div className="d-flex align-items-center">
                                    <span className="me-3">Show:</span>
                                    <select 
                                        className="form-select form-select-sm me-3" 
                                        style={{ width: 'auto' }}
                                        value={logsPerPage}
                                        onChange={(e) => handleLogsPerPageChange(parseInt(e.target.value))}
                                    >
                                        <option value={5}>5</option>
                                        <option value={7}>7</option>
                                        <option value={8}>8</option>
                                        <option value={10}>10</option>
                                        <option value={20}>20</option>
                                        <option value={50}>50</option>
                                    </select>
                                    <span className="text-muted">
                                        of {totalLogs} logs
                                    </span>
                                </div>
                            </div>
                            <div className="col-md-6">
                                <div className="d-flex justify-content-end align-items-center">
                                    <span className="me-3">
                                        Page {currentPage} of {totalPages}
                                    </span>
                                    <nav aria-label="Audit log pagination">
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
                                            {currentPage < (totalPages || 1) && (
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
                
            </div>
        </div>
    );
};

export default AuditLog; 