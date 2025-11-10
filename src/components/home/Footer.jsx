import React from "react";
import { useNavigate } from "react-router-dom";
import "./Footer.css";
import "bootstrap/dist/css/bootstrap.min.css";

const Footer = () => {
  const navigate = useNavigate();
  const currentYear = new Date().getFullYear();

  const scrollToSection = (sectionId) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth" });
    }
  };

  const footerLinks = {
    product: [
      { label: "Features", action: () => scrollToSection("features") },
      { label: "Pricing", action: () => navigate("/pricing") },
      { label: "Security", action: () => navigate("/security") },
      { label: "Integrations", action: () => navigate("/integrations") },
    ],
    company: [
      { label: "About Us", action: () => navigate("/about") },
      { label: "Careers", action: () => navigate("/careers") },
      { label: "Press", action: () => navigate("/press") },
      { label: "Contact", action: () => navigate("/contact") },
    ],
    support: [
      { label: "Help Center", action: () => navigate("/help") },
      { label: "Documentation", action: () => navigate("/docs") },
      { label: "API Reference", action: () => navigate("/api") },
      { label: "Status Page", action: () => navigate("/status") },
    ],
    legal: [
      { label: "Privacy Policy", action: () => navigate("/privacy") },
      { label: "Terms of Service", action: () => navigate("/terms") },
      { label: "Cookie Policy", action: () => navigate("/cookies") },
      { label: "GDPR", action: () => navigate("/gdpr") },
    ],
  };

  const socialLinks = [
    {
      icon: "fab fa-twitter",
      url: "https://twitter.com/securesys",
      label: "Twitter",
    },
    {
      icon: "fab fa-linkedin",
      url: "https://linkedin.com/company/securesys",
      label: "LinkedIn",
    },
    {
      icon: "fab fa-github",
      url: "https://github.com/securesys",
      label: "GitHub",
    },
    {
      icon: "fab fa-youtube",
      url: "https://youtube.com/securesys",
      label: "YouTube",
    },
  ];

  return (
    <footer className="footer">
      <div className="footer-main">
        <div className="container-fluid">
          <div className="row g-4">
            {/* Company Info */}
            <div className="col-lg-4 col-md-6">
              <div className="footer-brand">
                <div className="brand-icon">
                  <span className="shield-icon">🛡️</span>
                </div>
                <div className="brand-text">
                  <span className="brand-main">SecureSys</span>
                  <span className="brand-tagline">Enterprise Security</span>
                </div>
              </div>
              <p className="footer-description">
                Enterprise-grade security solutions with AI-powered threat
                detection, advanced encryption, and comprehensive compliance
                management for modern businesses.
              </p>
              <div className="social-links">
                {socialLinks.map((social, index) => (
                  <a
                    key={index}
                    href={social.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="social-link"
                    aria-label={social.label}
                  >
                    <i className={social.icon}></i>
                  </a>
                ))}
              </div>
            </div>

            {/* Product Links */}
            <div className="col-lg-2 col-md-6">
              <h5 className="footer-heading">Product</h5>
              <ul className="footer-links">
                {footerLinks.product.map((link, index) => (
                  <li key={index}>
                    <a
                      href="#"
                      onClick={(e) => {
                        e.preventDefault();
                        link.action();
                      }}
                    >
                      {link.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>

            {/* Company Links */}
            <div className="col-lg-2 col-md-6">
              <h5 className="footer-heading">Company</h5>
              <ul className="footer-links">
                {footerLinks.company.map((link, index) => (
                  <li key={index}>
                    <a
                      href="#"
                      onClick={(e) => {
                        e.preventDefault();
                        link.action();
                      }}
                    >
                      {link.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>

            {/* Support Links */}
            <div className="col-lg-2 col-md-6">
              <h5 className="footer-heading">Support</h5>
              <ul className="footer-links">
                {footerLinks.support.map((link, index) => (
                  <li key={index}>
                    <a
                      href="#"
                      onClick={(e) => {
                        e.preventDefault();
                        link.action();
                      }}
                    >
                      {link.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>

            {/* Contact Info */}
            <div className="col-lg-2 col-md-6">
              <h5 className="footer-heading">Contact</h5>
              <div className="contact-info">
                <div className="contact-item">
                  <i className="fas fa-map-marker-alt"></i>
                  <span>
                    Tinkune, Kathmandu
                    <br />
                    Nepal
                  </span>
                </div>
                <div className="contact-item">
                  <i className="fas fa-envelope"></i>
                  <a href="mailto:secure.security.system@gmail.com">
                    secure.security.system@gmail.com
                  </a>
                </div>
                <div className="contact-item">
                  <i className="fas fa-phone"></i>
                  <a href="tel:+977-9868497620">+977-9868497620</a>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer Bottom */}
      <div className="footer-bottom">
        <div className="container-fluid">
          <div className="row align-items-center">
            <div className="col-md-6">
              <p className="copyright">
                © {currentYear} SecureSys. All rights reserved.
              </p>
            </div>
            <div className="col-md-6">
              <div className="legal-links">
                {footerLinks.legal.map((link, index) => (
                  <a
                    key={index}
                    href="#"
                    onClick={(e) => {
                      e.preventDefault();
                      link.action();
                    }}
                  >
                    {link.label}
                  </a>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Newsletter Signup Modal Trigger */}
      <div className="newsletter-cta">
        <div className="container-fluid">
          <div className="newsletter-content">
            <h4>Stay Updated</h4>
            <p>Get the latest security insights and product updates</p>
            <button
              className="btn btn-primary"
              onClick={() => navigate("/newsletter")}
            >
              Subscribe to Newsletter
            </button>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
