const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Resend } = require('resend');

const app = express();
const PORT = process.env.PORT || 3001;

// --- CONFIGURATION ---
// In a real app, use environment variables for these
const RESEND_API_KEY = process.env.RESEND_API_KEY || 'YOUR_RESEND_API_KEY';
const JWT_SECRET = process.env.JWT_SECRET || 'YOUR_JWT_SECRET';
const resend = new Resend(RESEND_API_KEY);

// --- IN-MEMORY DATABASE (for demonstration) ---
// In a real app, you would use a proper database like PostgreSQL or MongoDB.
const users = [];

// --- MIDDLEWARE ---
app.use(cors()); // Allow requests from other origins
app.use(express.json()); // Parse JSON bodies

// --- API ROUTES ---

// 1. User Registration
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Check if user already exists
        if (users.find(u => u.email === email)) {
            return res.status(400).json({ message: 'El correo ya está registrado.' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate a verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');

        const newUser = {
            id: users.length + 1,
            name,
            email,
            password: hashedPassword,
            isVerified: false,
            verificationToken,
        };

        users.push(newUser);

        // Send verification email using Resend
        const verificationLink = `http://localhost:5173/verify-email?token=${verificationToken}`;
        
        await resend.emails.send({
            from: 'onboarding@resend.dev', // You can use this for testing
            to: email,
            subject: 'Activa tu cuenta en Chambitas',
            html: `¡Bienvenido a Chambitas! <br/><br/> Haz clic en el siguiente enlace para activar tu cuenta: <a href="${verificationLink}">${verificationLink}</a>`
        });

        res.status(201).json({ message: 'Usuario registrado. Por favor, revisa tu correo para activar tu cuenta.' });

    } catch (error) {
        console.error('Error en el registro:', error);
        res.status(500).json({ message: 'Error en el servidor.' });
    }
});

// 2. Email Verification
app.get('/api/auth/verify', (req, res) => {
    const { token } = req.query;

    const user = users.find(u => u.verificationToken === token);

    if (!user) {
        return res.status(400).send('<h1>Token de verificación inválido o expirado.</h1>');
    }

    user.isVerified = true;
    user.verificationToken = null; // Token is used, so invalidate it

    // Redirect to login page with a success message
    res.send('<h1>¡Cuenta verificada con éxito!</h1><p>Ya puedes <a href="http://localhost:5173/login">iniciar sesión</a>.</p>');
});

// 3. User Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = users.find(u => u.email === email);

        // Check if user exists
        if (!user) {
            return res.status(401).json({ message: 'Credenciales incorrectas.' });
        }

        // Check if account is verified
        if (!user.isVerified) {
            return res.status(403).json({ message: 'Tu cuenta no ha sido verificada. Por favor, revisa tu correo.' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Credenciales incorrectas.' });
        }

        // Generate JWT
        const token = jwt.sign(
            { userId: user.id, name: user.name, roles: ['client', 'worker'] }, // Mock roles for now
            JWT_SECRET,
            { expiresIn: '1h' } // Token expires in 1 hour
        );

        res.json({ token });

    } catch (error) {
        console.error('Error en el login:', error);
        res.status(500).json({ message: 'Error en el servidor.' });
    }
});


// Health check route
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Backend is running' });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});