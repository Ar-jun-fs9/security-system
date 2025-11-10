import { useState, useEffect } from "react";
import { api } from "../../services/api";
import "./Auth.css";

const AdminForgotPassword = ({ onBackToLogin }) => {
  const [step, setStep] = useState("email"); // "email", "otp", or "reset"
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [timer, setTimer] = useState(600); // 10 minutes in seconds
  const [isTimerRunning, setIsTimerRunning] = useState(false);

  // Timer effect
  useEffect(() => {
    let interval;
    if (isTimerRunning && timer > 0) {
      interval = setInterval(() => {
        setTimer((prev) => prev - 1);
      }, 1000);
    } else if (timer === 0) {
      setIsTimerRunning(false);
      setError("OTP expired. Please request a new one.");
    }
    return () => clearInterval(interval);
  }, [isTimerRunning, timer]);

  const startTimer = () => {
    setTimer(600);
    setIsTimerRunning(true);
  };

  const handleSendOTP = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    try {
      const response = await api.adminSendOTP(email);
      if (response.error) {
        setError(response.error);
        return;
      }
      setSuccess("OTP has been sent to your email");
      setStep("otp");
      startTimer();
    } catch (error) {
      setError("Failed to send OTP. Please try again.");
    }
  };

  const handleVerifyOTP = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    try {
      const response = await api.adminVerifyOTP(email, otp);
      if (response.error) {
        setError(response.error);
        return;
      }
      setSuccess("OTP verified successfully");
      setStep("reset");
      setIsTimerRunning(false);
    } catch (error) {
      setError("Failed to verify OTP. Please try again.");
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (newPassword !== confirmPassword) {
      setError("Passwords do not match!");
      return;
    }

    if (newPassword.length < 15) {
      setError("Password must be at least 15 characters long!");
      return;
    }

    try {
      const response = await api.adminResetPassword(newPassword);
      if (response.error) {
        setError(response.error);
        return;
      }

      setSuccess("Password has been reset successfully!");
      setTimeout(() => {
        onBackToLogin();
      }, 2000);
    } catch (error) {
      setError("Failed to reset password. Please try again.");
    }
  };

  const formatTime = (seconds) => {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
  };

  return (
    <div className="auth-form">
      <div className="auth-header">
        <i className="fas fa-key"></i>
        <h2>Admin Password Reset</h2>
      </div>

      {step === "email" ? (
        <form onSubmit={handleSendOTP}>
          <div className="mb-3">
            <label htmlFor="email" className="form-label">
              <i className="fas fa-envelope me-2"></i>Enter Admin Email
            </label>
            <input
              type="email"
              className="form-control"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          {error && <div className="alert alert-danger">{error}</div>}
          {success && <div className="alert alert-success">{success}</div>}

          <button type="submit" className="btn btn-primary w-100 mb-3">
            <i className="fas fa-paper-plane me-2"></i>Send OTP
          </button>

          <div className="text-center">
            <a href="#" onClick={onBackToLogin} className="text-decoration-none">
              <i className="fas fa-arrow-left me-2"></i>Back to Login
            </a>
          </div>
        </form>
      ) : step === "otp" ? (
        <form onSubmit={handleVerifyOTP}>
          <div className="mb-3">
            <label htmlFor="otp" className="form-label">
              <i className="fas fa-shield-alt me-2"></i>Enter OTP
            </label>
            <input
              type="text"
              className="form-control"
              id="otp"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              required
              maxLength="6"
              placeholder="Enter 6-digit OTP"
            />
            <small className="text-muted">
              OTP expires in: {formatTime(timer)}
            </small>
          </div>

          {error && <div className="alert alert-danger">{error}</div>}
          {success && <div className="alert alert-success">{success}</div>}

          <button type="submit" className="btn btn-primary w-100 mb-3">
            <i className="fas fa-check me-2"></i>Verify OTP
          </button>

          <div className="text-center">
            <button
              type="button"
              onClick={handleSendOTP}
              className="btn btn-link text-decoration-none"
              disabled={isTimerRunning}
            >
              <i className="fas fa-redo me-2"></i>
              {isTimerRunning ? "Resend OTP" : "Resend OTP"}
            </button>
            <br />
            <a
              href="#"
              onClick={() => setStep("email")}
              className="text-decoration-none"
            >
              <i className="fas fa-arrow-left me-2"></i>Back to Email
            </a>
          </div>
        </form>
      ) : (
        <form onSubmit={handleResetPassword}>
          <div className="mb-3">
            <label htmlFor="newPassword" className="form-label">
              <i className="fas fa-lock me-2"></i>New Password
            </label>
            <div className="password-input-container">
              <input
                type={showPassword ? "text" : "password"}
                className="form-control"
                id="newPassword"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                minLength="15"
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

          <div className="mb-3">
            <label htmlFor="confirmPassword" className="form-label">
              <i className="fas fa-lock me-2"></i>Confirm Password
            </label>
            <div className="password-input-container">
              <input
                type={showConfirmPassword ? "text" : "password"}
                className="form-control"
                id="confirmPassword"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                minLength="15"
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

          {error && <div className="alert alert-danger">{error}</div>}
          {success && <div className="alert alert-success">{success}</div>}

          <button type="submit" className="btn btn-primary w-100 mb-3">
            <i className="fas fa-save me-2"></i>Reset Password
          </button>

          <div className="text-center">
            <a href="#" onClick={() => setStep("otp")} className="text-decoration-none">
              <i className="fas fa-arrow-left me-2"></i>Back to OTP
            </a>
          </div>
        </form>
      )}
    </div>
  );
};

export default AdminForgotPassword; 