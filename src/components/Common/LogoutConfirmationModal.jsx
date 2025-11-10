import React from 'react';
import './LogoutConfirmationModal.css';

const LogoutConfirmationModal = ({ onClose, onConfirm }) => {
    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content" onClick={e => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>Confirm Logout</h2>
                    <button className="close-button" onClick={onClose}>
                        <i className="fas fa-times"></i>
                    </button>
                </div>
                <div className="modal-body">
                    <div className="text-center">
                        <i className="fas fa-sign-out-alt fa-3x mb-3 text-primary"></i>
                        <p className="mb-4">Are you sure you want to logout?</p>
                        <div className="d-flex justify-content-center gap-3">
                            <button
                                className="btn btn-secondary"
                                onClick={onClose}
                            >
                                Cancel
                            </button>
                            <button
                                className="btn btn-primary"
                                onClick={onConfirm}
                            >
                                Yes, Logout
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default LogoutConfirmationModal; 