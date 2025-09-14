# Quick Email Setup - Get Emails Working in 5 Minutes!

## Option 1: Web3Forms (Recommended - Works Immediately)

### Step 1: Get Your Access Key
1. Go to [Web3Forms.com](https://web3forms.com/)
2. Click "Get Access Key"
3. Enter your email: `attendoservices@gmail.com`
4. Copy the access key (looks like: `A1B2C3D4-E5F6-7890-ABCD-EF1234567890`)

### Step 2: Update Your Code
Replace the current fetch call in `src/components/Contact.tsx` with:

```javascript
const response = await fetch('https://api.web3forms.com/submit', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    access_key: 'YOUR-ACCESS-KEY-HERE', // Replace with your actual access key
    name: formData.name,
    email: formData.email,
    message: formData.message,
    subject: `New Contact Form Message from ${formData.name}`,
  }),
});
```

### Step 3: Test
- Fill out your contact form
- Submit it
- Check your email at `attendoservices@gmail.com`

## Option 2: Formspree (Alternative)

### Step 1: Create Formspree Account
1. Go to [Formspree.io](https://formspree.io/)
2. Sign up with `attendoservices@gmail.com`
3. Create a new form
4. Copy the form endpoint

### Step 2: Update Code
Replace the fetch URL with your Formspree endpoint.

## Current Status
✅ Form works without errors  
✅ Messages stored locally  
⏳ Email sending ready (just need access key)

**Just get your Web3Forms access key and you'll receive emails immediately!**
