const API_URL = 'http://localhost:5000/api';

export const api = {
    // Register
    register: async (username, email, password) => {
        const response = await fetch(`${API_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, email, password }),
        });
        return response.json();
    },

    // Login
    login: async (username, password) => {
        const response = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });
        return response.json();
    },

    // Verify Email
    verifyEmail: async (token) => {
        const response = await fetch(`${API_URL}/auth/verify-email?token=${token}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
        });
        return response.json();
    },

    // Resend Verification Email
    resendVerification: async (email) => {
        const response = await fetch(`${API_URL}/auth/resend-verification`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email }),
        });
        return response.json();
    },

    // Send OTP
    sendOTP: async (email) => {
        const response = await fetch(`${API_URL}/auth/send-otp`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email }),
        });
        return response.json();
    },

    // Verify OTP
    verifyOTP: async (email, otp) => {
        const response = await fetch(`${API_URL}/auth/verify-otp`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, otp }),
        });
        return response.json();
    },

    // Forgot Password - Verify Email
    verifyEmailForPasswordReset: async (email) => {
        const response = await fetch(`${API_URL}/auth/forgot-password/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email }),
        });
        return response.json();
    },

    // Forgot Password - Change Password
    changePassword: async (email, newPassword) => {
        const response = await fetch(`${API_URL}/auth/forgot-password/change`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, newPassword }),
        });
        return response.json();
    },

    // Get User Profile
    getUserProfile: async () => {
        const response = await fetch(`${API_URL}/auth/profile`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
        });
        return response.json();
    },

    // Admin Login
    adminLogin: async (username, password) => {
        const response = await fetch(`${API_URL}/admin/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });
        return response.json();
    },

    // Admin Forgot Password
    adminForgotPassword: async (email) => {
        const response = await fetch(`${API_URL}/admin/send-otp`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email }),
        });
        return response.json();
    },

    // Admin Reset Password
    adminResetPassword: async (newPassword) => {
        const resetToken = localStorage.getItem('adminResetToken');
        if (!resetToken) {
            throw new Error('Reset token not found');
        }
        const response = await fetch(`${API_URL}/admin/reset-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ resetToken, newPassword }),
        });
        return response.json();
    },

    // Get Admin Profile
    getAdminProfile: async () => {
        const response = await fetch(`${API_URL}/admin/profile`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
            },
        });
        return response.json();
    },

    // Get Admin Login History
    getAdminLoginHistory: async () => {
        const response = await fetch(`${API_URL}/admin/login-history`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
            },
        });
        return response.json();
    },

    // Admin Send OTP
    adminSendOTP: async (email) => {
        const response = await fetch(`${API_URL}/admin/send-otp`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email }),
        });
        return response.json();
    },

    // Admin Verify OTP
    adminVerifyOTP: async (email, otp) => {
        const response = await fetch(`${API_URL}/admin/verify-otp`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, otp }),
        });
        return response.json();
    },

    // Get user statistics
    getUserStatistics: async () => {
        try {
            const response = await fetch(`${API_URL}/admin/user-statistics`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
                    'Content-Type': 'application/json'
                }
            });
            return await response.json();
        } catch (error) {
            return { error: 'Failed to fetch user statistics' };
        }
    },

    // Get All Users
    getAllUsers: async (page = 1, limit = 8) => {
        const response = await fetch(`${API_URL}/admin/users?page=${page}&limit=${limit}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
            },
        });
        return response.json();
    },

    // Get User Details
    getUserDetails: async (userId) => {
        const response = await fetch(`${API_URL}/admin/users/${userId}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
            },
        });
        return response.json();
    },

    // Add User
    addUser: async (userData) => {
        const response = await fetch(`${API_URL}/admin/users`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
            },
            body: JSON.stringify(userData),
        });
        return response.json();
    },

    // Delete User
    deleteUser: async (userId) => {
        const response = await fetch(`${API_URL}/admin/users/${userId}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
            },
        });
        return response.json();
    },

    // Get blocked users
    getBlockedUsers: async () => {
        try {
            const response = await fetch(`${API_URL}/auth/blocked-users`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
                    'Content-Type': 'application/json'
                }
            });
            return await response.json();
        } catch (error) {
            return { error: 'Failed to fetch blocked users' };
        }
    },

    // Unblock user
    unblockUser: async (username) => {
        try {
            const response = await fetch(`${API_URL}/auth/unblock-user`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username })
            });
            return await response.json();
        } catch (error) {
            return { error: 'Failed to unblock user' };
        }
    },

    // Update user role
    updateUserRole: async (userId, role) => {
        try {
            const response = await fetch(`${API_URL}/admin/users/${userId}/role`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
                },
                body: JSON.stringify({ role }),
            });
            return response.json();
        } catch (error) {
            return { error: error.response?.data?.error || 'Failed to update user role' };
        }
    },

    // Verify Admin Password
    verifyAdminPassword: async (password) => {
        try {
            const response = await fetch(`${API_URL}/admin/verify-password`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password })
            });
            return await response.json();
        } catch (error) {
            return { error: 'Failed to verify admin password' };
        }
    },

    // Check profile update eligibility
    checkProfileUpdateEligibility: async () => {
        try {
            const response = await fetch(`${API_URL}/auth/profile/update-eligibility`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`,
                    'Content-Type': 'application/json'
                }
            });
            return await response.json();
        } catch (error) {
            return { error: 'Failed to check profile update eligibility' };
        }
    },

    // Update user profile
    updateProfile: async (username, email) => {
        try {
            const response = await fetch(`${API_URL}/auth/profile/update`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, email })
            });
            return await response.json();
        } catch (error) {
            return { error: 'Failed to update profile' };
        }
    },
}; 