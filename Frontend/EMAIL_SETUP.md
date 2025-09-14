# Email Setup Guide

To enable email sending from your contact form, you have two options:

## Option 1: Formspree (Recommended - Easier Setup)

### 1. Create Formspree Account
1. Go to [Formspree.io](https://formspree.io/)
2. Sign up for a free account
3. Verify your email address

### 2. Create a New Form
1. Click "New Form"
2. Name it "Attendo Contact Form"
3. Set the email to `attendoservices@gmail.com`
4. Copy the form endpoint (looks like: `https://formspree.io/f/xaybzwkd`)

### 3. Update Contact Component
Replace `YOUR_FORM_ID` in `src/components/Contact.tsx` with your actual form ID:

```javascript
const response = await fetch('https://formspree.io/f/YOUR_ACTUAL_FORM_ID', {
  // ... rest of the code
});
```

### 4. Test the Form
- Fill out the contact form on your website
- Submit it
- Check your email at `attendoservices@gmail.com`

## Option 2: EmailJS (More Advanced)

### 1. Create EmailJS Account
1. Go to [EmailJS.com](https://www.emailjs.com/)
2. Sign up for a free account
3. Verify your email address

### 2. Add Email Service
1. In EmailJS dashboard, go to "Email Services"
2. Click "Add New Service"
3. Choose "Gmail" or "Outlook"
4. Connect your email account (attendoservices@gmail.com)
5. Note down the **Service ID** (e.g., `service_attendo`)

### 3. Create Email Template
1. Go to "Email Templates"
2. Click "Create New Template"
3. Use this template:

**Subject:** New Contact Form Message from {{from_name}}

**Content:**
```
Name: {{from_name}}
Email: {{from_email}}
Message: {{message}}

This message was sent from your Attendo contact form.
```

4. Note down the **Template ID** (e.g., `template_contact`)

### 4. Get Public Key
1. Go to "Account" → "API Keys"
2. Copy your **Public Key**

### 5. Update Contact Component
Uncomment the EmailJS import and replace the Formspree code with:

```javascript
import emailjs from '@emailjs/browser';

const result = await emailjs.send(
  'YOUR_SERVICE_ID', // Replace with your actual Service ID
  'YOUR_TEMPLATE_ID', // Replace with your actual Template ID
  {
    from_name: formData.name,
    from_email: formData.email,
    message: formData.message,
    to_email: 'attendoservices@gmail.com'
  },
  'YOUR_PUBLIC_KEY' // Replace with your actual Public Key
);
```

## Quick Start (Recommended)
Use **Formspree** - it's the easiest option and works immediately!
