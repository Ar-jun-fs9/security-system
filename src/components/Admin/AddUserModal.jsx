import React, { useState } from 'react';
import './AddUserModal.css';

const AddUserModal = ({ onClose, onAddUser }) => {
    const [formData, setFormData] = useState({
        username: '',
        email: '',
        password: '',
        confirmPassword: '',
        registerMethod: 'email',
        role: 'user' // Default role
    });
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);

        // Validate form
        if (!formData.username || !formData.email || !formData.password || !formData.role) {
            setError('All fields are required');
            return;
        }

        if (formData.password !== formData.confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        if (formData.password.length < 8) {
            setError('Password must be at least 8 characters long');
            return;
        }

        setLoading(true);
        try {
            await onAddUser(formData);
            onClose();
        } catch (err) {
            setError(err.message || 'Failed to add user');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content" onClick={e => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>Add New User</h2>
                    <button className="close-button" onClick={onClose}>
                        <i className="fas fa-times"></i>
                    </button>
                </div>
                <div className="modal-body">
                    <form onSubmit={handleSubmit}>
                        {error && (
                            <div className="alert alert-danger" role="alert">
                                {error}
                            </div>
                        )}
                        
                        <div className="row mb-3">
                            <div className="col-md-6">
                        <div className="form-group">
                                    <label htmlFor="username"><i className="fas fa-user me-2"></i>Username</label>
                            <input
                                type="text"
                                id="username"
                                name="username"
                                className="form-control"
                                value={formData.username}
                                onChange={handleChange}
                                placeholder="Enter username"
                                required
                            />
                        </div>
                            </div>
                            <div className="col-md-6">
                        <div className="form-group">
                                    <label htmlFor="email"><i className="fas fa-envelope me-2"></i>Email</label>
                            <input
                                type="email"
                                id="email"
                                name="email"
                                className="form-control"
                                value={formData.email}
                                onChange={handleChange}
                                placeholder="Enter email"
                                required
                            />
                                </div>
                            </div>
                        </div>

                        <div className="row mb-3">
                            <div className="col-md-6">
                        <div className="form-group">
                                    <label htmlFor="password"><i className="fas fa-lock me-2"></i>Password</label>
                                    <div className="password-input-container">
                            <input
                                            type={showPassword ? "text" : "password"}
                                id="password"
                                name="password"
                                className="form-control"
                                value={formData.password}
                                onChange={handleChange}
                                placeholder="Enter password"
                                required
                            />
                                        <button
                                            type="button"
                                            className="password-toggle"
                                            onClick={() => setShowPassword(!showPassword)}
                                        >
                                            <i className={`fas fa-${showPassword ? "eye-slash" : "eye"}`}></i>
                                        </button>
                                    </div>
                                </div>
                        </div>
                            <div className="col-md-6">
                        <div className="form-group">
                                    <label htmlFor="confirmPassword"><i className="fas fa-lock me-2"></i>Confirm Password</label>
                                    <div className="password-input-container">
                            <input
                                            type={showConfirmPassword ? "text" : "password"}
                                id="confirmPassword"
                                name="confirmPassword"
                                className="form-control"
                                value={formData.confirmPassword}
                                onChange={handleChange}
                                placeholder="Confirm password"
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

                        <div className="row mb-4">
                            <div className="col-md-6">
                        <div className="form-group">
                                    <label htmlFor="role"><i className="fas fa-user-tag me-2"></i>Role</label>
                            <select
                                id="role"
                                name="role"
                                className="form-select"
                                value={formData.role}
                                onChange={handleChange}
                                required
                            >
                                <option value="user">User</option>
                                <option value="admin">Admin</option>
                            </select>
                        </div>
                            </div>
                            <div className="col-md-6">
                        <div className="form-group">
                                    <label htmlFor="registerMethod"><i className="fas fa-globe me-2"></i>Registration Method</label>
                            <select
                                id="registerMethod"
                                name="registerMethod"
                                className="form-select"
                                value={formData.registerMethod}
                                onChange={handleChange}
                                required
                            >
                                <option value="email">Email</option>
                                <option value="google">Google</option>
                                <option value="github">GitHub</option>
                            </select>
                                </div>
                            </div>
                        </div>

                        <div className="form-actions text-end">
                            <button
                                type="button"
                                className="btn btn-secondary me-2"
                                onClick={onClose}
                                disabled={loading}
                            >
                                Cancel
                            </button>
                            <button
                                type="submit"
                                className="btn btn-primary"
                                disabled={loading}
                            >
                                {loading ? (
                                    <>
                                        <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                                        Adding...
                                    </>
                                ) : (
                                    'Add User'
                                )}
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    );
};

export default AddUserModal; 