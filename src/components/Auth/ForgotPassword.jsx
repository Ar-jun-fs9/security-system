import { useState, useEffect } from "react";
import { api } from "../../services/api";
import "./Auth.css";

const ForgotPassword = ({ onBackToLogin }) => {
  const [step, setStep] = useState("verify"); // "verify", "otp", or "change"
  const [email, setEmail] = useState("");
  const [userInfo, setUserInfo] = useState(null);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState("");
  const [otp, setOtp] = useState("");
  const [timer, setTimer] = useState(60);
  const [isTimerRunning, setIsTimerRunning] = useState(false);

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
    setTimer(60);
    setIsTimerRunning(true);
  };

  const handleVerifyEmail = async (e) => {
    e.preventDefault();
    setError("");

    try {
      const response = await api.sendOTP(email);

      if (response.error) {
        setError(response.error);
        return;
      }

      setUserInfo(response.user);
      setStep("otp");
      startTimer();
    } catch (error) {
      setError("Failed to send OTP. Please try again.");
    }
  };

  const handleVerifyOTP = async (e) => {
    e.preventDefault();
    setError("");

    try {
      const response = await api.verifyOTP(email, otp);

      if (response.error) {
        setError(response.error);
        return;
      }

      setStep("change");
      setIsTimerRunning(false);
    } catch (error) {
      setError("Invalid OTP. Please try again.");
    }
  };

  const handleResendOTP = async () => {
    setError("");
    try {
      const response = await api.sendOTP(email);
      if (response.error) {
        setError(response.error);
        return;
      }
      startTimer();
    } catch (error) {
      setError("Failed to resend OTP. Please try again.");
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setError("");

    // Clear error after 1 second
    const showError = (message) => {
      setError(message);
      // setNewPassword("");
      // setConfirmPassword("");
      setTimeout(() => {
        setError("");
      }, 3000); // Increased timeout to 3 seconds for better readability
    };

    if (newPassword !== confirmPassword) {
      showError("Passwords do not match!");
      return;
    }

    if (newPassword.length < 15) {
      showError("Password must be at least 15 characters long!");
      return;
    }

    try {
      const response = await api.changePassword(email, newPassword);

      if (response.error) {
        showError(response.error);
        return;
      }

      // Show success message
      const successMessage = document.createElement("div");
      successMessage.className = "success-message";
      successMessage.innerHTML = `
        <i class="fas fa-check-circle"></i>
        <span>Password changed successfully!</span>
      `;
      document.body.appendChild(successMessage);

      // Navigate back to login
      setTimeout(() => {
        successMessage.remove();
        onBackToLogin();
      }, 2000);
    } catch (error) {
      showError(error.message || "Password change failed. Please try again.");
    }
  };

  return (
    <div className="auth-form">
      <div className="auth-header">
        <i className="fas fa-key"></i>
        <h2>Forgot Password</h2>
      </div>

      {step === "verify" ? (
        <form onSubmit={handleVerifyEmail}>
          <div className="mb-3">
            <label htmlFor="email" className="form-label">
              <i className="fas fa-envelope me-2"></i>Enter Email
            </label>
            <input
              type="email"
              className="form-control"
              autoComplete="off"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          {error && <div className="alert alert-danger">{error}</div>}

          <button type="submit" className="btn btn-primary w-100 mb-3">
            <i className="fas fa-check me-2"></i>Send OTP
          </button>

          <div className="text-center">
            <a
              href="#"
              onClick={onBackToLogin}
              className="text-decoration-none"
            >
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
              OTP expires in: {timer} seconds
            </small>
          </div>

          {error && <div className="alert alert-danger">{error}</div>}

          <button type="submit" className="btn btn-primary w-100 mb-3">
            <i className="fas fa-check me-2"></i>Verify OTP
          </button>

          <div className="text-center">
            <button
              type="button"
              onClick={handleResendOTP}
              className="btn btn-link text-decoration-none"
              disabled={isTimerRunning}
            >
              <i className="fas fa-redo me-2"></i>
              {isTimerRunning ? "Resend OTP" : "Resend OTP"}
            </button>
            <br />
            <a
              href="#"
              onClick={() => setStep("verify")}
              className="text-decoration-none"
            >
              <i className="fas fa-arrow-left me-2"></i>Back to Email
            </a>
          </div>
        </form>
      ) : (
        <form onSubmit={handleChangePassword}>
          {userInfo && (
            <div className="mb-3">
              <div className="alert alert-info">
                <i className="fas fa-user me-2"></i>
                <strong>Account:</strong> {userInfo.username}
              </div>
            </div>
          )}

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
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
              >
                <i
                  className={`fas fa-${showPassword ? "eye-slash" : "eye"}`}
                ></i>
              </button>
            </div>
          </div>

          <div className="mb-3">
            <label htmlFor="confirmPassword" className="form-label">
              <i className="fas fa-lock me-2"></i>Confirm New Password
            </label>
            <div className="password-input-container">
              <input
                type={showConfirmPassword ? "text" : "password"}
                className="form-control"
                id="confirmPassword"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
              >
                <i
                  className={`fas fa-${
                    showConfirmPassword ? "eye-slash" : "eye"
                  }`}
                ></i>
              </button>
            </div>
          </div>

          {error && <div className="alert alert-danger">{error}</div>}

          <button type="submit" className="btn btn-primary w-100 mb-3">
            <i className="fas fa-key me-2"></i>Change Password
          </button>

          <div className="text-center">
            <a
              href="#"
              onClick={() => setStep("otp")}
              className="text-decoration-none"
            >
              <i className="fas fa-arrow-left me-2"></i>Back to OTP
              Verification
            </a>
          </div>
        </form>
      )}
    </div>
  );
};

export default ForgotPassword;
