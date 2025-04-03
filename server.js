const express = require("express");
const cookieParser = require("cookie-parser");
const csrf = require("csrf");
const dotenv = require("dotenv");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const cors = require("cors");

dotenv.config();

const port = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || "secret";

const users = []; 
const sessions = {};
const secureCookieOptions = () => ({
  httpOnly: true,
  secure: true,
  sameSite: "strict",
});

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: "http://localhost:3001",
    credentials: true,
  })
);

app.get("/csrf-token", (req, res) => {
  const csrfToken = new csrf().create(SECRET_KEY);
  res.json({ csrfToken });
});

// Ruta de registro
app.post("/register", async (req, res) => {
  const { username, password, csrfToken } = req.body;

  if (!csrf().verify(SECRET_KEY, csrfToken)) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }

  // Validación de usuario
  if (!usernameRegex.test(username)) {
    console.log("Nombre de usuario recibido:", username);
    console.log("Resultado de la validación:", usernameRegex.test(username));
    return res.status(400).json({ error: "Usuario no válido." });
}


  

  // Validación de contraseña (según imagen proporcionada)
  const passwordRegex = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({ error: "Contraseña no cumple los requisitos." });
  }

  // Normalizar usuario
  const normalizedUser = username.toLowerCase();
  
  // Hashing del usuario y la contraseña
  const hashedUser = crypto.createHash("sha1").update(normalizedUser).digest("hex");
  const hashedPassword = await bcrypt.hash(password, 12);

  // Verificar si el usuario ya existe
  if (users.find((user) => user.username === hashedUser)) {
    return res.status(400).json({ error: "El usuario ya está registrado." });
  }

  // Guardar usuario
  users.push({ username: hashedUser, password: hashedPassword });
  res.status(201).json({ message: "Cuenta creada correctamente." });
});

// Ruta de login
app.post("/login", async (req, res) => {
  const { username, password, csrfToken } = req.body;

  if (!csrf().verify(SECRET_KEY, csrfToken)) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }
  
  const normalizedUser = username.toLowerCase();
  const hashedUser = crypto.createHash("sha1").update(normalizedUser).digest("hex");

  const user = users.find((user) => user.username === hashedUser);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Usuario o contraseña incorrectos." });
  }

  const sessionId = crypto.randomBytes(16).toString("base64url");
  sessions[sessionId] = { username: hashedUser };
  res.cookie("sessionId", sessionId, secureCookieOptions());
  res.status(200).json({ message: "Login successful" });
});

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
