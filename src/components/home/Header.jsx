import React, { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import "./Header.css";
import "bootstrap/dist/css/bootstrap.min.css";

const Header = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50);
    };

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const handleNavClick = (path) => {
    navigate(path);
    setIsMobileMenuOpen(false);
  };

  const scrollToSection = (sectionId) => {
    if (location.pathname !== "/") {
      navigate("/");
      setTimeout(() => {
        const element = document.getElementById(sectionId);
        if (element) {
          element.scrollIntoView({ behavior: "smooth" });
        }
      }, 100);
    } else {
      const element = document.getElementById(sectionId);
      if (element) {
        element.scrollIntoView({ behavior: "smooth" });
      }
    }
    setIsMobileMenuOpen(false);
  };

  const navItems = [
    {
      label: "Features",
      action: () => scrollToSection("features"),
      path: "/features",
    },
    {
      label: "Pricing",
      action: () => handleNavClick("/pricing"),
      path: "/pricing",
    },
    { label: "About", action: () => handleNavClick("/about"), path: "/about" },
    {
      label: "Contact",
      action: () => handleNavClick("/contact"),
      path: "/contact",
    },
  ];

  return (
    <nav
      className={`navbar navbar-expand-lg navbar-light fixed-top transition-all ${
        isScrolled ? "navbar-scrolled" : "navbar-transparent"
      }`}
    >
      <div className="container-fluid">
        <div
          className="navbar-brand d-flex align-items-center"
          onClick={() => handleNavClick("/")}
          style={{ cursor: "pointer" }}
        >
          <div className="brand-icon">
            <span className="shield-icon">🛡️</span>
          </div>
          <div className="brand-text">
            <span className="brand-main">SecureSystem</span>
            <span className="brand-tagline">Enterprise Security</span>
          </div>
        </div>

        <button
          className={`navbar-toggler ${isMobileMenuOpen ? "active" : ""}`}
          type="button"
          onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          aria-expanded={isMobileMenuOpen}
          aria-label="Toggle navigation"
        >
          <span className="navbar-toggler-icon"></span>
        </button>

        <div
          className={`collapse navbar-collapse ${
            isMobileMenuOpen ? "show" : ""
          }`}
          id="navbarNav"
        >
          <ul className="navbar-nav mx-auto">
            {navItems.map((item, index) => (
              <li key={index} className="nav-item">
                <a
                  className={`nav-link ${
                    location.pathname === item.path ? "active" : ""
                  }`}
                  onClick={(e) => {
                    e.preventDefault();
                    item.action();
                  }}
                  href="#"
                >
                  {item.label}
                </a>
              </li>
            ))}
          </ul>
          <div className="d-flex align-items-center">
            <button
              className="btn btn-outline-primary me-2 btn-login"
              onClick={() => handleNavClick("/auth")}
            >
              <i className="fas fa-sign-in-alt me-1"></i>
              Login
            </button>
            <button
              className="btn btn-primary btn-signup"
              onClick={() => handleNavClick("/auth?tab=register")}
            >
              <i className="fas fa-user-plus me-1"></i>
              Get Started
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Menu Overlay */}
      {isMobileMenuOpen && (
        <div
          className="mobile-menu-overlay"
          onClick={() => setIsMobileMenuOpen(false)}
        >
          <div
            className="mobile-menu-content"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mobile-nav-items">
              {navItems.map((item, index) => (
                <a
                  key={index}
                  className={`mobile-nav-link ${
                    location.pathname === item.path ? "active" : ""
                  }`}
                  onClick={(e) => {
                    e.preventDefault();
                    item.action();
                  }}
                  href="#"
                >
                  {item.label}
                </a>
              ))}
            </div>
            <div className="mobile-auth-buttons">
              <button
                className="btn btn-outline-primary w-100 mb-2"
                onClick={() => handleNavClick("/auth")}
              >
                <i className="fas fa-sign-in-alt me-2"></i>
                Login
              </button>
              <button
                className="btn btn-primary w-100"
                onClick={() => handleNavClick("/auth?tab=register")}
              >
                <i className="fas fa-user-plus me-2"></i>
                Get Started
              </button>
            </div>
          </div>
        </div>
      )}
    </nav>
  );
};

export default Header;
