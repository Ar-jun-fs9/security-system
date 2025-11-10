import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../services/api';

const EmailVerification = () => {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const [status, setStatus] = useState('verifying');
    const [error, setError] = useState(null);

    useEffect(() => {
        const verifyEmail = async () => {
            try {
                const token = searchParams.get('token');
                if (!token) {
                    setError('Verification token is missing');
                    setStatus('error');
                    return;
                }

                const response = await api.verifyEmail(token);
                if (response.error) {
                    setError(response.error);
                    setStatus('error');
                } else {
                    setStatus('success');
                    // Redirect to auth page after 3 seconds
                    setTimeout(() => {
                        navigate('/auth?tab=login', { replace: true });
                    }, 3000);
                }
            } catch (error) {
                console.error('Verification error:', error);
                setError('Failed to verify email. Please try again.');
                setStatus('error');
            }
        };

        verifyEmail();
    }, [searchParams, navigate]);

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
            <div className="max-w-md w-full space-y-8">
                <div>
                    <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
                        Email Verification
                    </h2>
                </div>
                <div className="mt-8 space-y-6">
                    {status === 'verifying' && (
                        <div className="text-center">
                            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
                            <p className="mt-4 text-gray-600">Verifying your email...</p>
                        </div>
                    )}
                    {status === 'success' && (
                        <div className="text-center">
                            <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100">
                                <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                                </svg>
                            </div>
                            <p className="mt-4 text-gray-600">Email verified successfully! Redirecting to login...</p>
                        </div>
                    )}
                    {status === 'error' && (
                        <div className="text-center">
                            <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100">
                                <svg className="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                                </svg>
                            </div>
                            <p className="mt-4 text-red-600">{error}</p>
                            <button
                                onClick={() => navigate('/auth?tab=login', { replace: true })}
                                className="mt-4 inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
                            >
                                Go to Login
                            </button>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default EmailVerification; 