import ReCAPTCHA from "react-google-recaptcha";
import { useState, useEffect, useRef } from "react";
import { api } from "../../services/api";
import { useNavigate } from "react-router-dom";
import "./Auth.css";
import { FaArrowLeft } from "react-icons/fa";

const Login = ({ onSwitchToRegister, onForgotPassword, isActive }) => {
  const navigate = useNavigate();
  const recaptchaRef = useRef(null);
  const [showPassword, setShowPassword] = useState(false);
  const [formData, setFormData] = useState({
    username: "",
    password: "",
    rememberMe: false,
  });
  const [isCaptchaVerified, setIsCaptchaVerified] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (isActive) {
      setFormData({ username: "", password: "", rememberMe: false });
      setShowPassword(false);
      setIsCaptchaVerified(false);
      setError("");
    }
  }, [isActive]);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");

    if (!isCaptchaVerified) {
      setError("Please complete the reCAPTCHA verification!");
      return;
    }

    try {
      const response = await api.login(formData.username, formData.password);

      if (response.error) {
        // Handle specific error cases
        if (response.error.includes("User not found")) {
          setError("Username does not exist");
        } else if (response.error.includes("Invalid password")) {
          setError(response.message || "Password is wrong");
        } else {
          setError(response.error);
        }

        // Reset form fields
        // setFormData({ username: "", password: "", rememberMe: false });
        // setIsCaptchaVerified(false);
        // if (recaptchaRef.current) {
        //   recaptchaRef.current.reset();
        // }

        // Clear error message after 2 seconds
        setTimeout(() => {
          setError("");
        }, 2000);

        return;
      }

      // Store the token
      if (response.token) {
        localStorage.setItem("token", response.token);
      }

      if (formData.rememberMe) {
        localStorage.setItem(
          "rememberedUser",
          JSON.stringify({ username: formData.username })
        );
      } else {
        localStorage.removeItem("rememberedUser");
      }

      // Show success message
      const successMessage = document.createElement("div");
      successMessage.className = "success-message";
      successMessage.innerHTML = `
        <i class="fas fa-check-circle"></i>
        <span>Login successful!</span>
      `;
      document.body.appendChild(successMessage);

      // // Reset form fields
      // setFormData({ username: "", password: "", rememberMe: false });
      // setIsCaptchaVerified(false);
      // if (recaptchaRef.current) {
      //   recaptchaRef.current.reset();
      // }

      // Redirect to dashboard after a short delay
      setTimeout(() => {
        successMessage.remove();
        navigate("/dashboard");
      }, 1000);
    } catch (error) {
      setError("Login failed. Please try again.");

      // Reset form fields on error
      setFormData({ username: "", password: "", rememberMe: false });
      setIsCaptchaVerified(false);
      if (recaptchaRef.current) {
        recaptchaRef.current.reset();
      }

      // Clear error message after 2 seconds
      setTimeout(() => {
        setError("");
      }, 2000);
    }
  };

  const handleInputChange = (e) => {
    const { id, value, type, checked } = e.target;
    setFormData((prev) => ({
      ...prev,
      [id === "loginUsername"
        ? "username"
        : id === "loginPassword"
        ? "password"
        : "rememberMe"]: type === "checkbox" ? checked : value,
    }));
  };

  const handleCaptchaChange = (value) => {
    setIsCaptchaVerified(!!value);
  };

  const handleForgotPassword = (e) => {
    e.preventDefault();
    onForgotPassword();
  };

  const handleSocialLogin = (provider) => {
    // Implement social login functionality
    alert(`${provider} login will be implemented soon!`);
  };

  return (
    <div className="auth-container">
      <div className="auth-form-container">
        <button
          className="btn btn-link position-absolute top-0 start-0 text-decoration-none"
          onClick={() => navigate("/")}
          style={{ color: "#0d6efd" }}
        >
          <FaArrowLeft className="me-2" />
        </button>

        <form id="loginFormElement" onSubmit={handleLogin}>
          <div className="mb-3">
            <label htmlFor="loginUsername" className="form-label">
              <i className="fas fa-user me-2"></i>Username
            </label>
            <input
              type="text"
              className="form-control"
              id="loginUsername"
              autoComplete="off"
              required
              value={formData.username}
              onChange={handleInputChange}
            />
          </div>

          <div className="mb-2">
            <label htmlFor="loginPassword" className="form-label">
              <i className="fas fa-lock me-2"></i>Password
            </label>
            <div className="password-input-container">
              <input
                type={showPassword ? "text" : "password"}
                className="form-control"
                id="loginPassword"
                required
                value={formData.password}
                onChange={handleInputChange}
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

          <div className="mb-3 form-check">
            <input
              type="checkbox"
              className="form-check-input"
              id="rememberMe"
              checked={formData.rememberMe}
              onChange={handleInputChange}
            />
            <label className="form-check-label" htmlFor="rememberMe">
              Remember me
            </label>
          </div>

          <div className="mb-4 recaptcha-container">
            <ReCAPTCHA
              ref={recaptchaRef}
              sitekey="your site key here"
              onChange={handleCaptchaChange}
            />
          </div>

          {error && <div className="alert alert-danger mb-3">{error}</div>}

          <button
            type="submit"
            className={`btn btn-primary w-100 mb-2 mt-1 ${
              !isCaptchaVerified ? "captcha-unverified" : ""
            }`}
            onClick={(e) => {
              if (!isCaptchaVerified) {
                e.preventDefault();
                e.stopPropagation();
              }
            }}
          >
            <i className="fas fa-sign-in-alt me-2"></i>Login
          </button>

          <div className="text-center mb-2">
            <a
              href="#"
              onClick={handleForgotPassword}
              className="text-decoration-none"
            >
              Forgot Password?
            </a>
          </div>

          <div className="social-login-container">
            <div className="divider">
              <span>or continue with</span>
            </div>

            <div className="social-buttons">
              <button
                type="button"
                className="btn btn-outline-danger w-100 mb-2"
                onClick={() => handleSocialLogin("Google")}
              >
                <i className="fab fa-google me-2"></i>Login with Google
              </button>
              <button
                type="button"
                className="btn btn-outline-primary w-100"
                onClick={() => handleSocialLogin("Facebook")}
              >
                <i className="fab fa-facebook me-2"></i>Login with Facebook
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

export default Login;
