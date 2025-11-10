import React, { useState, useRef } from 'react';
import './UserDetailsModal.css';

const UserDetailsModal = ({ user, onClose, onDeleteUser, onBlockUser }) => {
    const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
    const [deleting, setDeleting] = useState(false);
    const [showBlockConfirm, setShowBlockConfirm] = useState(false);
    const [blocking, setBlocking] = useState(false);
    const [blockUntilDate, setBlockUntilDate] = useState('');
    const [blockSuccess, setBlockSuccess] = useState(false);
    const dateInputRef = useRef(null);

    const handleDeleteClick = () => {
        setShowDeleteConfirm(true);
    };

    const handleDeleteConfirm = async () => {
        setDeleting(true);
        try {
            await onDeleteUser(user.id);
            onClose();
        } catch (error) {
            console.error('Failed to delete user:', error);
            setDeleting(false);
            setShowDeleteConfirm(false);
        }
    };

    const handleBlockConfirm = async () => {
      if (!blockUntilDate) {
        alert('Please select a date to block the user until.');
        return;
      }

      setBlocking(true);
      try {
        await onBlockUser(user.id, blockUntilDate);
        setBlockSuccess(true);
        setTimeout(() => {
          onClose();
        }, 3000);
      } catch (error) {
        console.error('Failed to block user:', error);
        alert('Failed to block user. Please try again.');
        setBlockSuccess(false); // Ensure success message is not shown on error
        setBlockUntilDate(''); // Reset date on error
        setShowBlockConfirm(false); // Go back to original view
      } finally {
        setBlocking(false);
        }
    };

    const handleDeleteCancel = () => {
        setShowDeleteConfirm(false);
    };

    if (!user) return null;

    const formatDate = (dateString) => {
        return new Date(dateString).toLocaleString();
    };

    const getDeviceInfo = (userAgent) => {
        if (!userAgent) return 'Unknown';
        const isMobile = /Mobile|Android|iP(hone|od)|IEMobile|BlackBerry|Kindle|Silk-Accelerated|(hpw|web)OS|Opera M(obi|ini)/.test(userAgent);
        const isTablet = /(tablet|ipad|playbook|silk)|(android(?!.*mobi))/i.test(userAgent);
        if (isMobile) return 'Mobile Device';
        if (isTablet) return 'Tablet';
        return 'Desktop';
    };

    const getBrowserInfo = (userAgent) => {
        if (!userAgent) return 'Unknown';
        if (userAgent.includes('Chrome')) return 'Chrome';
        if (userAgent.includes('Firefox')) return 'Firefox';
        if (userAgent.includes('Safari')) return 'Safari';
        if (userAgent.includes('Edge')) return 'Edge';
        if (userAgent.includes('MSIE') || userAgent.includes('Trident/')) return 'Internet Explorer';
        return 'Other Browser';
    };

    return (
        <div 
  className="position-fixed top-0 start-0 w-100 h-100 bg-dark bg-opacity-50 d-flex justify-content-center align-items-center overflow-auto"
  style={{ zIndex: 1050 }}
  onClick={onClose}
>
  <div 
    className="bg-white rounded shadow-lg p-4 w-100"
    style={{ maxWidth: '900px', maxHeight: '90vh', overflowY: 'auto' }}
    onClick={e => e.stopPropagation()}
  >
    {/* Modal Header */}
    <div className="d-flex justify-content-between align-items-center border-bottom pb-3 mb-4">
      <h2 className="h4 mb-0">User Details</h2>
      <div className="d-flex gap-2">
      <button 
          className="btn btn-warning text-white"
          onClick={() => setShowBlockConfirm(true)}
          style={{ display: showDeleteConfirm || showBlockConfirm ? 'none' : 'inline-block' }}
        >
          <i className="fas fa-ban me-2"></i> Block User
        </button>
        
        <button 
          className="btn btn-danger"
          onClick={() => setShowDeleteConfirm(true)}
          style={{ display: showDeleteConfirm || showBlockConfirm ? 'none' : 'inline-block' }}
        >
          <i className="fas fa-trash-alt me-2"></i> Delete User
        </button>
        <button 
          className="btn btn-outline-secondary"
          onClick={onClose}
        >
          <i className="fas fa-times"></i>
        </button>
      </div>
    </div>

    {/* Modal Body */}
    <div>
      {showDeleteConfirm ? (
        <div className="text-center">
          <h3 className="mb-3">Confirm Delete</h3>
          <p>Are you sure you want to delete this user? This action cannot be undone.</p>
          <div className="d-flex justify-content-center gap-3 mt-4">
            <button
              className="btn btn-secondary"
              onClick={handleDeleteCancel}
              disabled={deleting}
            >
              Cancel
            </button>
            <button
              className="btn btn-danger"
              onClick={handleDeleteConfirm}
              disabled={deleting}
            >
              {deleting ? (
                <>
                  <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                  Deleting...
                </>
              ) : (
                'Delete User'
              )}
            </button>
          </div>
        </div>
      ) : showBlockConfirm ? (
        <div className="text-center">
          <h3 className="mb-3">Block User</h3>
          <p>Block {user.username} until a desired date.</p>
          <div className="mt-4 mb-3">
            <label htmlFor="blockUntil" className="form-label">Block Until Date:</label>
            <div className="date-input-container mx-auto" style={{ maxWidth: '250px' }}>
              <input
                type="date"
                id="blockUntil"
                className="form-control"
                value={blockUntilDate}
                onChange={(e) => setBlockUntilDate(e.target.value)}
                min={new Date().toISOString().split('T')[0]}
                ref={dateInputRef}
              />
              <i 
                className="fas fa-calendar-alt calendar-icon"
                onClick={() => dateInputRef.current.showPicker()}
              ></i>
            </div>
          </div>
          <div className="d-flex justify-content-center gap-3 mt-4">
            <button
              className="btn btn-secondary"
              onClick={() => { setShowBlockConfirm(false); setBlockUntilDate(''); }}
              disabled={blocking}
            >
              Cancel
            </button>
            <button
              className="btn btn-warning text-white"
              onClick={handleBlockConfirm}
              disabled={blocking || !blockUntilDate}
            >
              {blocking ? (
                <>
                  <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                  Blocking...
                </>
              ) : (
                'Block User'
              )}
            </button>
          </div>
        </div>
      ) : blockSuccess ? (
        <div className="text-center text-success">
            <i className="fas fa-check-circle fa-4x mb-3"></i>
            <h3 className="mb-3">User Blocked Successfully!</h3>
            <p className="lead">User <strong>{user.username}</strong> is now blocked until <strong>{formatDate(blockUntilDate)}</strong>.</p>
            <p className="text-muted mt-4">Closing in 3 seconds...</p>
        </div>
      ) : (
        <>
          {/* Basic Info */}
          <div className="mb-4">
            <h3 className="h5 mb-3 border-bottom pb-2">Basic Information</h3>
            <div className="row g-3">
              <div className="col-md-6"><strong>Username:</strong> {user.username}</div>
              <div className="col-md-6"><strong>Email:</strong> {user.email}</div>
              <div className="col-md-6">
                <strong>Role:</strong> 
                <span className={`badge ms-2 ${user.role === 'admin' ? 'bg-danger' : 'bg-primary'}`}>
                  {user.role ? user.role.charAt(0).toUpperCase() + user.role.slice(1) : 'User'}
                </span>
              </div>
              <div className="col-md-6"><strong>Registration Method:</strong> <span className="text-capitalize">{user.registerMethod}</span></div>
              <div className="col-md-6"><strong>Account Created:</strong> {formatDate(user.createdAt)}</div>
              <div className="col-md-6">
                <strong>Email Status:</strong> 
                <span className={`badge ms-2 ${user.emailVerified ? 'bg-success' : 'bg-warning text-dark'}`}>
                  {user.emailVerified ? 'Verified' : 'Not Verified'}
                </span>
              </div>
            </div>
          </div>

          {/* Login Info */}
          <div className="mb-4">
            <h3 className="h5 mb-3 border-bottom pb-2">Login Information</h3>
            <div className="row g-3">
              <div className="col-md-6"><strong>Login Count:</strong> {user.loginCount || 0}</div>
              <div className="col-md-6">
                <strong>Last Login:</strong> {user.lastLogin && user.loginCount > 0 ? formatDate(user.lastLogin) : 'No login detected'}
              </div>
              <div className="col-md-6">
                <strong>Last IP Address:</strong> {user.loginCount > 0 ? (user.ipAddress || 'N/A') : 'N/A'}
              </div>
              <div className="col-md-6">
                <strong>Last Device:</strong> {user.loginCount > 0 ? (user.userAgent ? getDeviceInfo(user.userAgent) : 'N/A') : 'N/A'}
              </div>
              <div className="col-md-6">
                <strong>Last Browser:</strong> {user.loginCount > 0 ? (user.userAgent ? getBrowserInfo(user.userAgent) : 'N/A') : 'N/A'}
              </div>
            </div>
          </div>

          {/* Security Info */}
          <div className="mb-4">
            <h3 className="h5 mb-3 border-bottom pb-2">Security Information</h3>
            <div className="row g-3">
              <div className="col-md-6"><strong>Password Changes:</strong> {user.passwordChangeCount || 0}</div>
              <div className="col-md-6"><strong>Last Password Change:</strong> {user.lastPasswordChange ? formatDate(user.lastPasswordChange) : 'No password changes yet'}</div>
            </div>
          </div>

          {/* Login History */}
          {user.loginHistory && user.loginHistory.length > 0 && (
            <div className="mb-3">
              <h3 className="h5 mb-3 border-bottom pb-2">Login History</h3>
              <div className="table-responsive">
                <table className="table table-striped table-bordered">
                  <thead className="table-light">
                    <tr>
                      <th>Date & Time</th>
                      <th>IP Address</th>
                      <th>Device</th>
                      <th>Browser</th>
                    </tr>
                  </thead>
                  <tbody>
                    {user.loginHistory.map((login, index) => (
                      <tr key={index}>
                        <td>{formatDate(login.login_date)}</td>
                        <td>{login.ip_address}</td>
                        <td>{getDeviceInfo(login.user_agent)}</td>
                        <td>{getBrowserInfo(login.user_agent)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  </div>
</div>

    );
};

export default UserDetailsModal; 