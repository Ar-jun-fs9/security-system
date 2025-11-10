import React, { useState, useEffect } from 'react';
import { Navigate, useLocation } from 'react-router-dom';

const ProtectedRoute = ({ children, type = 'user' }) => {
    const [isAuthenticated, setIsAuthenticated] = useState(null);
    const location = useLocation();
    const token = localStorage.getItem(type === 'admin' ? 'adminToken' : 'token');

    useEffect(() => {
        const validateToken = async () => {
            if (!token) {
                setIsAuthenticated(false);
                return;
            }

            try {
                // You can add additional token validation here if needed
                // For example, checking if the token is expired
                const tokenData = JSON.parse(atob(token.split('.')[1]));
                const isExpired = tokenData.exp * 1000 < Date.now();

                if (isExpired) {
                    localStorage.removeItem(type === 'admin' ? 'adminToken' : 'token');
                    setIsAuthenticated(false);
                } else {
                    setIsAuthenticated(true);
                }
            } catch (error) {
                console.error('Token validation error:', error);
                localStorage.removeItem(type === 'admin' ? 'adminToken' : 'token');
                setIsAuthenticated(false);
            }
        };

        validateToken();
    }, [token, type]);

    if (isAuthenticated === null) {
        // Show loading state while checking authentication
        return <div className="flex items-center justify-center min-h-screen">
            <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
        </div>;
    }

    if (!isAuthenticated) {
        // Redirect to login page with return url
        const loginPath = type === 'admin' ? '/auth' : '/auth';
        return <Navigate to={loginPath} state={{ from: location.pathname }} replace />;
    }

    return children;
};

export default ProtectedRoute; 