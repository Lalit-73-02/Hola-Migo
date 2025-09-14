import { motion } from "framer-motion";
import { Github, Linkedin, Twitter, UserCheck, ArrowUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useCallback, useMemo, useState } from "react";

export default function Footer() {
  const [showPrivacy, setShowPrivacy] = useState(false);
  const [showTerms, setShowTerms] = useState(false);

  // Optimized scroll handlers
  const scrollToTop = useCallback(() => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  const scrollToSection = useCallback((href: string) => {
    const element = document.querySelector(href);
    if (element) {
      element.scrollIntoView({ behavior: "smooth" });
    }
  }, []);

  // Memoize static data
  const navItems = useMemo(
    () => [
      { name: "Home", href: "#home" },
      { name: "About", href: "#about" },
      { name: "Features", href: "#features" },
      { name: "Contact", href: "#contact" },
    ],
    []
  );

  const socialLinks = useMemo(
    () => [
      { icon: Github, href: "#", label: "GitHub" },
      { icon: Linkedin, href: "#", label: "LinkedIn" },
      { icon: Twitter, href: "#", label: "Twitter" },
    ],
    []
  );

  return (
    <>
      <footer className="relative overflow-hidden">
        {/* Background Pattern */}
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-accent/5"></div>

        <div className="relative glass border-t border-primary/20">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 sm:gap-8">
              {/* Brand Section */}
              <div className="sm:col-span-1">
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, ease: "easeOut" }}
                  className="flex items-center space-x-2 mb-4"
                >
                  <UserCheck className="h-6 w-6 sm:h-8 sm:w-8 text-primary" />
                  <span className="text-xl sm:text-2xl font-bold gradient-text">
                    Attendo
                  </span>
                </motion.div>

                <motion.p
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, delay: 0.1, ease: "easeOut" }}
                  className="text-muted-foreground mb-6 text-sm sm:text-base"
                >
                  Revolutionizing attendance management with smart, secure, and
                  scalable solutions.
                </motion.p>

                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, delay: 0.2, ease: "easeOut" }}
                  className="flex space-x-3 sm:space-x-4"
                >
                  {socialLinks.map((social, index) => (
                    <a
                      key={index}
                      href={social.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-center w-8 h-8 sm:w-10 sm:h-10 bg-primary/10 hover:bg-primary/20 rounded-full transition-colors hover-glow"
                    >
                      <social.icon className="h-4 w-4 sm:h-5 sm:w-5 text-primary" />
                    </a>
                  ))}
                </motion.div>
              </div>

              {/* Quick Links */}
              <div className="sm:col-span-1">
                <motion.h3
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, ease: "easeOut" }}
                  className="text-base sm:text-lg font-semibold mb-4"
                >
                  Quick Links
                </motion.h3>

                <motion.ul
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, delay: 0.1, ease: "easeOut" }}
                  className="space-y-2 sm:space-y-3"
                >
                  {navItems.map((item, index) => (
                    <li key={index}>
                      <button
                        onClick={() => scrollToSection(item.href)}
                        className="text-muted-foreground hover:text-primary transition-colors cursor-pointer text-sm sm:text-base"
                      >
                        {item.name}
                      </button>
                    </li>
                  ))}
                </motion.ul>
              </div>

              {/* Features */}
              <div className="sm:col-span-1">
                <motion.h3
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, ease: "easeOut" }}
                  className="text-base sm:text-lg font-semibold mb-4"
                >
                  Features
                </motion.h3>

                <motion.ul
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, delay: 0.1, ease: "easeOut" }}
                  className="space-y-2 sm:space-y-3 text-muted-foreground text-sm sm:text-base"
                >
                  <li>QR Code Attendance</li>
                  <li>Real-time Analytics</li>
                  <li>Mobile App</li>
                  <li>Admin Dashboard</li>
                </motion.ul>
              </div>

              {/* Contact Info */}
              <div className="sm:col-span-1">
                <motion.h3
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, ease: "easeOut" }}
                  className="text-base sm:text-lg font-semibold mb-4"
                >
                  Contact
                </motion.h3>

                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, delay: 0.1, ease: "easeOut" }}
                  className="space-y-2 sm:space-y-3 text-muted-foreground text-sm sm:text-base"
                >
                  <p>attendoservices@gmail.com</p>
                  <p>+91 98765 43210</p>
                  <p>
                    Government Polytechnic Kashipur <br />
                    Uttarakhand, India
                  </p>
                </motion.div>
              </div>
            </div>

            {/* Bottom Section */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.3, ease: "easeOut" }}
              className="flex flex-col sm:flex-row items-center justify-between pt-6 sm:pt-8 mt-6 sm:mt-8 border-t border-primary/20"
            >
              <p className="text-muted-foreground text-xs sm:text-sm mb-4 sm:mb-0 text-center sm:text-left">
                © 2025 Attendo. Built with ❤️ by{" "}
                <strong>
                  Manish Paliwal, Bhavesh Bisht, Sahil Chand, Lalit Kanyal
                </strong>{" "}
                <br /><strong>Team Ninja Hattori</strong>. All rights reserved.
              </p>

              <div className="flex items-center space-x-4 text-xs sm:text-sm">
                <span
                  onClick={() => setShowPrivacy(true)}
                  className="text-muted-foreground cursor-pointer hover:text-primary transition-colors"
                >
                  Privacy Policy
                </span>
                <span
                  onClick={() => setShowTerms(true)}
                  className="text-muted-foreground cursor-pointer hover:text-primary transition-colors"
                >
                  Terms of Service
                </span>
              </div>
            </motion.div>
          </div>
        </div>
      </footer>

      {/* Privacy Policy Modal */}
      {showPrivacy && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-lg max-w-lg w-full p-6">
            <h2 className="text-lg font-bold mb-4 dark:text-gray-900 ">Privacy Policy</h2>
            <p className="text-sm text-gray-600 mb-4">
              We respect your privacy. Our system collects only basic
              information such as name, roll number, and attendance data. This
              information is used solely for recording and managing attendance
              within educational institutions. We do not share this data with
              third parties.
            </p>
            <Button onClick={() => setShowPrivacy(false)}>Close</Button>
          </div>
        </div>
      )}

      {/* Terms of Service Modal */}
      {showTerms && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-lg max-w-lg w-full p-6">
            <h2 className="text-lg font-bold mb-4 dark:text-gray-900  ">Terms of Service</h2>
            <p className="text-sm text-gray-600 mb-4">
              This project is developed for educational purposes. By using the
              system, you agree to use it responsibly. Do not misuse or attempt
              to alter the system. Attendance data accuracy depends on entries
              made by authorized users. This is a student project and not a
              commercial application.
            </p>
            <Button onClick={() => setShowTerms(false)}>Close</Button>
          </div>
        </div>
      )}

      {/* Back to Top Button */}
      <motion.div
        initial={{ opacity: 0, scale: 0 }}
        whileInView={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="fixed bottom-4 sm:bottom-8 right-4 sm:right-8 z-40"
      >
        <Button
          onClick={scrollToTop}
          size="sm"
          className="w-10 h-10 sm:w-12 sm:h-12 rounded-full bg-primary hover:bg-primary/90 text-primary-foreground shadow-lg hover-glow animate-float"
        >
          <ArrowUp className="h-4 w-4 sm:h-5 sm:w-5" />
        </Button>
      </motion.div>
    </>
  );
}
