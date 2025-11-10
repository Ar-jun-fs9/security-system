import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../../services/api';

const AdminLogin = () => {
    const navigate = useNavigate();
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setLoading(true);

        try {
            const response = await api.adminLogin(username, password);
            if (response.error) {
                throw new Error(response.error);
            }

            // Store the token and admin info
            localStorage.setItem('adminToken', response.token);
            localStorage.setItem('adminInfo', JSON.stringify({
                id: response.admin.id,
                username: response.admin.username,
                email: response.admin.email,
                role: response.admin.role,
                isFromUserRegister: response.admin.isFromUserRegister
            }));

            // Navigate to admin dashboard
            navigate('/admin-dashboard');
        } catch (error) {
            setError(error.message || 'Failed to login');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div>
            {/* Render your form here */}
        </div>
    );
};

export default AdminLogin; 