const express = require('express');
const cookieParser = require('cookie-parser');
const csrf = require('csrf');
const dotenv = require('dotenv');
const crypto = require('crypto');
const cors = require('cors');
const bcrypt = require('bcryptjs');

dotenv.config();

const port = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'secret';

// Almacén en memoria para usuarios y sesiones
const users = [];
const sessions = {};

const secureCookieOptions = () => ({
    httpOnly: true,
    secure: false, 
    sameSite: 'strict' 
});

const app = express();

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Permite CORS 
app.use(cors({
    origin: 'http://localhost:3001',
    credentials: true
}));

app.get('/', (req, res) => {
    res.send('Hello World!');
});

// Endpoint para obtener un token CSRF válido
app.get('/csrf-token', (req, res) => {
    const csrfToken = new csrf().create(SECRET_KEY);
    res.json({ csrfToken });
});

// Función para validar contraseña
function validarPassword(password) {
    return (
        password.length >= 10 &&
        /[A-Z]/.test(password) &&
        /[a-z]/.test(password) &&
        /[0-9]/.test(password) &&
        /[^A-Za-z0-9]/.test(password)
    );
}

// Función para normalizar el usuario
function normalizarUsuario(usuario) {
    return usuario.toLowerCase();
}

// Función para generar hash del usuario
function obtenerHashUsuario(usuarioNorm) {
    return crypto.createHash('sha1').update(usuarioNorm).digest('hex');
}

// registro
app.post('/register', async (req, res) => {
    const { usuario, password1, password2, csrfToken } = req.body;

    // Verifica el token CSRF para prevenir ataques cross-site
    if (!csrf().verify(SECRET_KEY, csrfToken)) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    // Validaciones básicas de campos
    if (!usuario || !password1 || !password2) {
        return res.status(400).json({ error: 'Todos los campos son requeridos.' });
    }
    if (password1 !== password2) {
        return res.status(400).json({ error: 'Las contraseñas no coinciden.' });
    }

    // Validación de nombre de usuario 
    const regexpUsuario = /^[a-zA-Z][0-9a-zA-Z]{5,49}$/;
    if (!regexpUsuario.test(usuario)) {
        return res.status(400).json({ error: 'NOMBRE INVÁLIDO PARA USUARIO' });
    }

    // Validación de contraseña 
    if (!validarPassword(password1)) {
        return res.status(400).json({ error: 'CONTRASEÑA INSEGURA' });
    }

    // Normaliza y hashea el usuario para evitar duplicados 
    const usuarioNorm = normalizarUsuario(usuario);
    const hashUsuario = obtenerHashUsuario(usuarioNorm);

    // Verifica si el usuario ya existe
    if (users.find(u => u.hashUsuario === hashUsuario)) {
        return res.status(409).json({ error: 'El usuario ya existe.' });
    }

    // Hashea la contraseña antes de guardar
    const hashPassword = await bcrypt.hash(password1, 10); // Salt rounds seguros
    users.push({ hashUsuario, username: usuarioNorm, password: hashPassword });

    res.status(201).json({ message: 'CUENTA CREADA CORRECTAMENTE' });
});

// login
app.post('/login', async (req, res) => {
    const { username, password, csrfToken } = req.body;

    // Verifica el token CSRF
    if (!csrf().verify(SECRET_KEY, csrfToken)) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    // Validación de campos
    if (!username || !password) {
        return res.status(400).json({ error: 'Usuario y contraseña son requeridos.' });
    }

    // Normaliza y busca el usuario
    const usernameNorm = normalizarUsuario(username);
    const hashUsuario = obtenerHashUsuario(usernameNorm);
    const user = users.find(u => u.hashUsuario === hashUsuario);
    if (!user) {
        return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
    }

    // Verifica la contraseña hasheada
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
        return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
    }

    // Crea una sesión y la asocia a una cookie segura
    const sessionId = crypto.randomBytes(16).toString('base64url');
    sessions[sessionId] = { username: user.username };
    res.cookie('sessionId', sessionId, secureCookieOptions());
    res.status(200).json({ message: 'Login succesful' });
});

// ENDPOINT para obtener el usuario autenticado a partir de la cookie de sesión
app.get('/me', (req, res) => {
    const sessionId = req.cookies.sessionId;
    if (!sessionId || !sessions[sessionId]) {
        return res.status(401).json({ error: 'No autenticado' });
    }
    res.json({ username: sessions[sessionId].username });
});

// Inicia el servidor 
app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});
