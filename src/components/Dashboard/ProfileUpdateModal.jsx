import React, { useState, useEffect } from 'react';
import { api } from '../../services/api';
import './ProfileUpdateModal.css';

const ProfileUpdateModal = ({ show, onClose, onUpdate, currentUser }) => {
    const [formData, setFormData] = useState({
        username: '',
        email: ''
    });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [eligibility, setEligibility] = useState(null);

    useEffect(() => {
        if (show && currentUser) {
            setFormData({
                username: currentUser.username || '',
                email: currentUser.email || ''
            });
            checkEligibility();
        }
    }, [show, currentUser]);

    const checkEligibility = async () => {
        try {
            const response = await api.checkProfileUpdateEligibility();
            if (response.error) {
                setError(response.error);
            } else {
                setEligibility(response);
            }
        } catch (error) {
            setError('Failed to check update eligibility');
        }
    };

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        setSuccess('');

        // Check if any changes were made
        if (formData.username === currentUser.username && formData.email === currentUser.email) {
            setError('Please update username or email to make changes to your profile');
            setLoading(false);
            return;
        }

        try {
            const response = await api.updateProfile(formData.username, formData.email);
            
            if (response.error) {
                setError(response.error);
            } else {
                setSuccess('Profile updated successfully!');
                onUpdate(response.user);
                setTimeout(() => {
                    setSuccess('');
                    onClose();
                }, 1000); // Close quickly after success
            }
        } catch (error) {
            setError('Failed to update profile');
        } finally {
            setLoading(false);
        }
    };

    const handleClose = () => {
        setFormData({ username: '', email: '' });
        setError('');
        setSuccess('');
        setEligibility(null);
        onClose();
    };

    if (!show) return null;

    return (
        <div className="modal-overlay" onClick={handleClose}>
            <div className={`modal-content profile-update-modal ${error ? 'error-state' : ''}`} onClick={e => e.stopPropagation()}>
                <div className="modal-header">
                    <h3>
                        <i className="fas fa-user-edit me-2"></i>
                        Update Profile
                    </h3>
                    <button className="close-button" onClick={handleClose}>
                        <i className="fas fa-times"></i>
                    </button>
                </div>
                
                <div className="modal-body">
                    {success ? (
                        <div className="alert alert-success">
                            <i className="fas fa-check-circle me-2"></i>
                            {success}
                        </div>
                    ) : (
                        <>
                            {eligibility && !eligibility.canUpdate && (
                                <div className="alert alert-warning">
                                    <i className="fas fa-clock me-2"></i>
                                    Profile update is not available yet. You can update your profile again after{' '}
                                    <strong>{new Date(eligibility.nextUpdateAllowed).toLocaleDateString()}</strong>
                                </div>
                            )}

                            {error && (
                                <div className="alert alert-danger">
                                    <i className="fas fa-exclamation-triangle me-2"></i>
                                    {error}
                                </div>
                            )}

                            <form onSubmit={handleSubmit}>
                                <div className="mb-3">
                                    <label htmlFor="username" className="form-label">
                                        <i className="fas fa-user me-2"></i>
                                        Username
                                    </label>
                                    <input
                                        type="text"
                                        className="form-control"
                                        id="username"
                                        name="username"
                                        value={formData.username}
                                        onChange={handleInputChange}
                                        required
                                        disabled={!eligibility?.canUpdate || loading}
                                        minLength="3"
                                        maxLength="50"
                                    />
                                    <div className="form-text">
                                        Username must be between 3 and 50 characters
                                    </div>
                                </div>

                                <div className="mb-3">
                                    <label htmlFor="email" className="form-label">
                                        <i className="fas fa-envelope me-2"></i>
                                        Email
                                    </label>
                                    <input
                                        type="email"
                                        className="form-control"
                                        id="email"
                                        name="email"
                                        value={formData.email}
                                        onChange={handleInputChange}
                                        required
                                        disabled={!eligibility?.canUpdate || loading}
                                    />
                                    <div className="form-text">
                                        Please enter a valid email address
                                    </div>
                                </div>

                                {eligibility && eligibility.canUpdate && (
                                    <div className="alert alert-info">
                                        <i className="fas fa-info-circle me-2"></i>
                                        After updating, you'll need to wait 2 months before making another update.
                                    </div>
                                )}

                                <div className="d-grid gap-2">
                                    <button
                                        type="submit"
                                        className="btn btn-primary"
                                        disabled={!eligibility?.canUpdate || loading}
                                    >
                                        {loading ? (
                                            <>
                                                <span className="spinner-border spinner-border-sm me-2" role="status"></span>
                                                Updating...
                                            </>
                                        ) : (
                                            <>
                                                <i className="fas fa-save me-2" ></i>
                                                Update Profile
                                            </>
                                        )}
                                    </button>
                                    <button
                                        type="button"
                                        className="btn btn-secondary"
                                        onClick={handleClose}
                                        disabled={loading}
                                    >
                                        Cancel
                                    </button>
                                </div>
                            </form>
                        </>
                    )}
                </div>
            </div>
        </div>
    );
};

export default ProfileUpdateModal; 