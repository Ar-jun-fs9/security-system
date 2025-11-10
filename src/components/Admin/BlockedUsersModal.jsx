import React, { useState, useEffect } from 'react';
import { api } from '../../services/api';
import './AdminDashboard.css';

const BlockedUsersModal = ({ show, onClose, onUnblock }) => {
    const [blockedUsers, setBlockedUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [showConfirmDialog, setShowConfirmDialog] = useState(false);
    const [selectedUser, setSelectedUser] = useState(null);

    useEffect(() => {
        if (show) {
            fetchBlockedUsers();
        }
    }, [show]);

    const fetchBlockedUsers = async () => {
        setLoading(true);
        try {
            const response = await api.getBlockedUsers();
            if (response.error) {
                setError(response.error);
            } else {
                setBlockedUsers(response.blockedUsers);
            }
        } catch (error) {
            setError('Failed to fetch blocked users');
        } finally {
            setLoading(false);
        }
    };

    const handleUnblockClick = (user) => {
        setSelectedUser(user);
        setShowConfirmDialog(true);
    };

    const handleConfirmUnblock = async () => {
        try {
            const response = await api.unblockUser(selectedUser.username);
            if (response.error) {
                setError(response.error);
            } else {
                // Remove the unblocked user from the list
                setBlockedUsers(blockedUsers.filter(user => user.username !== selectedUser.username));
                onUnblock();
            }
        } catch (error) {
            setError('Failed to unblock user');
        } finally {
            setShowConfirmDialog(false);
            setSelectedUser(null);
        }
    };

    const handleCancelUnblock = () => {
        setShowConfirmDialog(false);
        setSelectedUser(null);
    };

    if (!show) return null;

    return (
        <div className="modal-overlay">
            <div className="modal-content blocked-users-modal">
                <div className="modal-header">
                    <h3>Blocked Users</h3>
                    <button className="close-button" onClick={onClose}>
                        <i className="fas fa-times"></i>
                    </button>
                </div>
                <div className="modal-body">
                    {loading ? (
                        <div className="text-center">
                            <div className="spinner-border text-primary" role="status">
                                <span className="visually-hidden">Loading...</span>
                            </div>
                        </div>
                    ) : error ? (
                        <div className="alert alert-danger">{error}</div>
                    ) : blockedUsers.length === 0 ? (
                        <div className="text-center">
                            <p>No blocked users found</p>
                        </div>
                    ) : (
                        <div className="table-responsive">
                            <table className="table table-hover">
                                <thead className="table-light">
                                    <tr>
                                        <th>Username</th>
                                        <th>Blocked Since</th>
                                        <th>Block Expires</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {blockedUsers.map((user) => (
                                        <tr key={user.username}>
                                            <td>{user.username}</td>
                                            <td>{new Date(user.last_attempt).toLocaleString()}</td>
                                            <td>{new Date(user.block_expires_at).toLocaleString()}</td>
                                            <td>
                                                <button
                                                    className="btn btn-success btn-sm"
                                                    onClick={() => handleUnblockClick(user)}
                                                >
                                                    <i className="fas fa-unlock"></i> Unblock
                                                </button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </div>

            {/* Confirmation Dialog */}
            {showConfirmDialog && (
                <div className="modal-overlay">
                    <div className="modal-content confirmation-dialog">
                        <div className="modal-header">
                            <h4>Confirm Unblock</h4>
                        </div>
                        <div className="modal-body">
                            <p>Are you sure you want to unblock user <strong>{selectedUser?.username}</strong>?</p>
                            <div className="confirmation-buttons">
                                <button
                                    className="btn btn-secondary"
                                    onClick={handleCancelUnblock}
                                >
                                    No, Cancel
                                </button>
                                <button
                                    className="btn btn-success"
                                    onClick={handleConfirmUnblock}
                                >
                                    Yes, Unblock
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default BlockedUsersModal; 