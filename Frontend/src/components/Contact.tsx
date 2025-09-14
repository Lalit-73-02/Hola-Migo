import { motion } from "framer-motion";
import { useInView } from "framer-motion";
import { useRef, useState, useCallback, useMemo } from "react";
import { Send, Github, Linkedin, Twitter, Mail, Phone, MapPin } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
// import emailjs from '@emailjs/browser'; // Uncomment when EmailJS is set up

export default function Contact() {
  const ref = useRef(null);
  const isInView = useInView(ref, { once: true, margin: "-50px" });
  const { toast } = useToast();
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    message: ""
  });
  const [loading, setLoading] = useState(false);

  // Handle input change
  const handleInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      setFormData((prev) => ({
        ...prev,
        [e.target.name]: e.target.value,
      }));
    },
    []
  );

  // Submit form -> handle locally (no external dependencies)
  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setLoading(true);

      try {
        // Send email using a simple and reliable service
        const response = await fetch('https://formsubmit.co/attendoservices@gmail.com', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            name: formData.name,
            email: formData.email,
            message: formData.message,
            _subject: `New Contact Form Message from ${formData.name}`,
            _captcha: false
          })
        });

        if (response.ok) {
          // Store message in localStorage as backup
          const messages = JSON.parse(localStorage.getItem('contactMessages') || '[]');
          const newMessage = {
            id: Date.now(),
            ...formData,
            timestamp: new Date().toISOString()
          };
          messages.push(newMessage);
          localStorage.setItem('contactMessages', JSON.stringify(messages));

          // Show success message
          toast({
            title: "✅ Email Sent Successfully!",
            description: "Your message has been sent to attendoservices@gmail.com! 🎉",
          });
          
          // Reset form
          setFormData({ name: "", email: "", message: "" });
          
          console.log(`✅ Email sent from ${formData.name} (${formData.email}):`, formData.message);
        } else {
          throw new Error('Failed to send email');
        }
      } catch (error) {
        console.error('Error saving message:', error);
        toast({
          title: "❌ Error",
          description: "Could not save message. Please try again later.",
          variant: "destructive",
        });
      } finally {
        setLoading(false);
      }
    },
    [formData, toast]
  );

  // Social links
  const socialLinks = useMemo(
    () => [
      { icon: Github, href: "#", label: "GitHub" },
      { icon: Linkedin, href: "#", label: "LinkedIn" },
      { icon: Twitter, href: "#", label: "Twitter" },
    ],
    []
  );

  // Contact Info
  const contactInfo = useMemo(
    () => [
      { icon: Mail, text: "attendoservices@gmail.com" },
      { icon: Phone, text: "+91 98765 43210" },
      { icon: MapPin, text: "Government Polytechnic Kashipur, Pincode 244713" },
    ],
    []
  );

  return (
    <section id="contact" className="py-12 sm:py-16 lg:py-20 bg-muted/30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Heading */}
        <motion.div
          ref={ref}
          initial={{ opacity: 0 }}
          animate={isInView ? { opacity: 1 } : { opacity: 0 }}
          transition={{ duration: 0.6, ease: "easeOut" }}
          className="text-center mb-12 sm:mb-16"
        >
          <motion.h2
            initial={{ opacity: 0, y: 30 }}
            animate={isInView ? { opacity: 1, y: 0 } : { opacity: 0, y: 30 }}
            transition={{ delay: 0.2, duration: 0.6, ease: "easeOut" }}
            className="text-3xl sm:text-4xl md:text-5xl font-bold mb-4 sm:mb-6"
          >
            Get In <span className="gradient-text">Touch</span>
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 30 }}
            animate={isInView ? { opacity: 1, y: 0 } : { opacity: 0, y: 30 }}
            transition={{ delay: 0.4, duration: 0.6, ease: "easeOut" }}
            className="text-lg sm:text-xl text-muted-foreground max-w-2xl sm:max-w-3xl mx-auto px-4"
          >
            Have questions about Attendo? We'd love to hear from you. 
            Send us a message and we'll respond as soon as possible.
          </motion.p>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 sm:gap-12">
          {/* Contact Form */}
          <motion.div
            initial={{ opacity: 0, x: -50 }}
            animate={isInView ? { opacity: 1, x: 0 } : { opacity: 0, x: -50 }}
            transition={{ delay: 0.6, duration: 0.6, ease: "easeOut" }}
            className="glass p-6 sm:p-8 rounded-xl sm:rounded-2xl"
          >
            <h3 className="text-xl sm:text-2xl font-semibold mb-6">Send us a message</h3>
            <form onSubmit={handleSubmit} className="space-y-4 sm:space-y-6">
              <Input
                type="text"
                name="name"
                placeholder="Your Name"
                value={formData.name}
                onChange={handleInputChange}
                required
                className="h-12 sm:h-14"
              />
              <Input
                type="email"
                name="email"
                placeholder="Your Email"
                value={formData.email}
                onChange={handleInputChange}
                required
                className="h-12 sm:h-14"
              />
              <Textarea
                name="message"
                placeholder="Your Message"
                value={formData.message}
                onChange={handleInputChange}
                required
                rows={5}
                className="resize-none"
              />
              <Button
                type="submit"
                disabled={loading}
                className="w-full h-12 sm:h-14 text-base sm:text-lg"
              >
                {loading ? "Sending..." : (
                  <>
                    <Send className="mr-2 h-4 w-4 sm:h-5 sm:w-5" />
                    Send Message
                  </>
                )}
              </Button>
            </form>
          </motion.div>

          {/* Contact Info */}
          <motion.div
            initial={{ opacity: 0, x: 50 }}
            animate={isInView ? { opacity: 1, x: 0 } : { opacity: 0, x: 50 }}
            transition={{ delay: 0.8, duration: 0.6, ease: "easeOut" }}
            className="space-y-6 sm:space-y-8"
          >
            <div className="glass p-6 sm:p-8 rounded-xl sm:rounded-2xl">
              <h3 className="text-xl sm:text-2xl font-semibold mb-6">Contact Information</h3>
              <div className="space-y-4">
                {contactInfo.map((info, index) => (
                  <div key={index} className="flex items-center space-x-4">
                    <div className="flex items-center justify-center w-10 h-10 bg-primary/10 rounded-full flex-shrink-0">
                      <info.icon className="h-5 w-5 text-primary" />
                    </div>
                    <span className="text-muted-foreground">{info.text}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="glass p-6 sm:p-8 rounded-xl sm:rounded-2xl">
              <h3 className="text-xl sm:text-2xl font-semibold mb-6">Follow Us</h3>
              <div className="flex space-x-4">
                {socialLinks.map((social, index) => (
                  <motion.a
                    key={index}
                    href={social.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    whileHover={{ scale: 1.1 }}
                    whileTap={{ scale: 0.9 }}
                    className="flex items-center justify-center w-10 h-10 sm:w-12 sm:h-12 bg-primary/10 hover:bg-primary/20 rounded-full transition-colors"
                  >
                    <social.icon className="h-5 w-5 sm:h-6 sm:w-6 text-primary" />
                  </motion.a>
                ))}
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
