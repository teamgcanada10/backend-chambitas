require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const sgMail = require('@sendgrid/mail');

const app = express();
const PORT = process.env.PORT || 3001;

// --- SendGrid Configuration ---
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// --- Middleware ---
// CORS Configuration
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:3000',
  'https://chambitas.teamgplay.online',
];

const corsOptions = {
  origin: allowedOrigins,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(bodyParser.json());

// --- In-memory Database ---
let users = [];

// --- Helper Functions ---
const generateToken = (user) => {
    return jwt.sign(
        { id: user.id, email: user.email, roles: user.roles },
        process.env.JWT_SECRET || 'supersecret', 
        { expiresIn: '1h' }
    );
};

// --- Routes ---

// Register a new user
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Todos los campos son requeridos.' });
    }

    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
        return res.status(400).json({ message: 'El correo ya está registrado.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const emailVerificationToken = crypto.randomBytes(32).toString('hex');

    const newUser = {
        id: users.length + 1,
        name,
        email,
        password: hashedPassword,
        roles: ['user'], // Default role
        isEmailVerified: false,
        emailVerificationToken,
    };

    users.push(newUser);

    // --- Send Verification Email ---
    const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${emailVerificationToken}`;
    const msg = {
        to: newUser.email,
        from: 'noreply@teamgplay.online', // Use your verified sender identity
        subject: '¡Bienvenido a Chambitas! Verifica tu correo electrónico',
        html: `
            <h1>¡Gracias por registrarte!</h1>
            <p>Por favor, haz clic en el siguiente enlace para verificar tu correo electrónico y activar tu cuenta:</p>
            <a href="${verificationLink}">${verificationLink}</a>
            <p>Si no te registraste en Chambitas, por favor ignora este correo.</p>
        `,
    };

    try {
        await sgMail.send(msg);
        console.log('Verification email sent to:', newUser.email);
        res.status(201).json({ message: 'Registro exitoso. Por favor, revisa tu correo para activar tu cuenta.' });
    } catch (error) {
        console.error("Error sending verification email:", error.response ? error.response.body : error);
        // Even if email fails, user is created. You might want to handle this differently.
        res.status(500).json({ message: 'Usuario registrado, pero ocurrió un error al enviar el correo de verificación.' });
    }
});

// Verify email address
app.post('/api/auth/verify-email', (req, res) => {
    const { token } = req.body;
    if (!token) {
        return res.status(400).json({ message: 'Token no proporcionado.' });
    }

    const user = users.find(u => u.emailVerificationToken === token);

    if (!user) {
        return res.status(400).json({ message: 'Token de verificación inválido o expirado.' });
    }

    user.isEmailVerified = true;
    user.emailVerificationToken = null; // Invalidate the token

    console.log(`Email verified for user: ${user.email}`);
    res.status(200).json({ message: 'Correo verificado exitosamente. Ya puedes iniciar sesión.' });
});


// Login user
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);

    if (!user) {
        return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    // Check if email is verified before allowing login
    if (!user.isEmailVerified) {
        return res.status(403).json({ message: 'Por favor, verifica tu correo electrónico antes de iniciar sesión.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: 'Credenciales inválidas.' });
    }

    const token = generateToken(user);
    res.json({ token });
});


app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
