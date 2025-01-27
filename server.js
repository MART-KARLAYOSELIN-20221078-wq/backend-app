require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const mysql = require("mysql2");
const cors = require("cors");

const app = express();
app.use(bodyParser.json());

// Permitir solicitudes desde el frontend
app.use(cors({
    origin: ["http://localhost:3000", 'https://recuperacionyos.recuperaciokarla.ticsgrupoc.site'],// Dirección del cliente
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
}));

// Configuración de la base de datos MySQL con pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Probar la conexión al inicio
pool.getConnection((err, connection) => {
    if (err) {
        console.error("Error al conectar a la base de datos:", err);
        process.exit(1);
    }
    console.log("Conexión al pool de MySQL exitosa");
    connection.release();
});

// Configuración de Nodemailer
const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
    },
});

// Rutas de la API
app.post("/api/register", async (req, res) => {
    const {
        firstName,
        lastName,
        motherLastName,
        username,
        email,
        password,
        phone,
        secretQuestion,
        secretAnswer,
    } = req.body;

    pool.query(
        "SELECT * FROM users WHERE username = ? OR email = ?",
        [username, email],
        async (err, results) => {
            if (err) return res.status(500).send({ message: "Error en el servidor" });
            if (results.length > 0)
                return res.status(400).send({ message: "El usuario o correo ya existe" });

            const hashedPassword = await bcrypt.hash(password, 10);

            pool.query(
                `INSERT INTO users 
                (first_name, last_name, mother_last_name, username, email, password, phone, secret_question, secret_answer) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    firstName,
                    lastName,
                    motherLastName,
                    username,
                    email,
                    hashedPassword,
                    phone,
                    secretQuestion,
                    secretAnswer,
                ],
                (err, results) => {
                    if (err) {
                        console.error("Error al insertar en la base de datos:", err);
                        return res.status(500).send({ message: "Error al registrar el usuario" });
                    }
                    res.send({ message: "Usuario registrado con éxito" });
                }
            );
        }
    );
});

app.post("/api/login", (req, res) => {
    const { username, password } = req.body;

    pool.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
        if (err) return res.status(500).send({ message: "Error en el servidor" });
        if (results.length === 0) return res.status(404).send({ message: "Usuario no encontrado" });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).send({ message: "Contraseña incorrecta" });

        const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, {
            expiresIn: "1h",
        });

        res.send({
            message: "Inicio de sesión exitoso",
            token,
            username: user.username,
        });
    });
});

app.post("/api/get-secret-question", (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).send({ message: "El correo es obligatorio" });
    }

    pool.query("SELECT secret_question FROM users WHERE email = ?", [email], (err, results) => {
        if (err) {
            console.error("Error al consultar la base de datos:", err);
            return res.status(500).send({ message: "Error en el servidor" });
        }

        if (results.length === 0) {
            return res.status(404).send({ message: "Correo no encontrado" });
        }

        const secretQuestion = results[0].secret_question;
        res.send({ secretQuestion });
    });
});

app.post("/api/forgot-password", (req, res) => {
    const { email } = req.body;

    pool.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
        if (err) return res.status(500).send({ message: "Error en el servidor" });
        if (results.length === 0) return res.status(404).send({ message: "Correo no encontrado" });

        const user = results[0];
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "15m" });
        const resetLink = `http://localhost:3000/reset-password/${token}`;

        await transporter.sendMail({
            from: `"Soporte" <${process.env.GMAIL_USER}>`,
            to: email,
            subject: "Recuperación de contraseña",
            html: `<p>Para restablecer tu contraseña, haz clic en el siguiente enlace:</p>
            <a href="${resetLink}">${resetLink}</a>`,
        });

        res.send({ message: "Correo enviado con éxito" });
    });
});

app.post("/api/recover-password", (req, res) => {
    const { email, secretQuestion, secretAnswer } = req.body;

    pool.query(
        "SELECT * FROM users WHERE email = ? AND secret_question = ?",
        [email, secretQuestion],
        (err, results) => {
            if (err) {
                console.error("Error en la consulta SQL:", err);
                return res.status(500).send({ message: "Error en el servidor" });
            }

            if (results.length === 0) {
                return res.status(404).send({ message: "Usuario no encontrado o pregunta incorrecta" });
            }

            const user = results[0];
            if (
                user.secret_answer.trim().toLowerCase() ===
                secretAnswer.trim().toLowerCase()
            ) {
                return res.send({ message: "Respuesta correcta, procede a restablecer la contraseña" });
            } else {
                return res.status(401).send({ message: "Respuesta secreta incorrecta" });
            }
        }
    );
});

app.post("/api/reset-password/:token", async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const hashedPassword = await bcrypt.hash(password, 10);

        pool.query(
            "UPDATE users SET password = ? WHERE id = ?",
            [hashedPassword, decoded.id],
            (err, results) => {
                if (err) {
                    console.error("Error al actualizar la contraseña en la base de datos:", err);
                    return res.status(500).send({ message: "Error en el servidor" });
                }

                if (results.affectedRows === 0) {
                    return res.status(404).send({ message: "Usuario no encontrado" });
                }

                res.send({ message: "Contraseña restablecida con éxito" });
            }
        );
    } catch (error) {
        res.status(400).send({ message: "Token inválido o expirado" });
    }
});

app.post("/api/reset-password-direct", async (req, res) => {
    const { email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        pool.query(
            "UPDATE users SET password = ? WHERE email = ?",
            [hashedPassword, email],
            (err, results) => {
                if (err) {
                    console.error("Error al actualizar la contraseña en la base de datos:", err);
                    return res.status(500).send({ message: "Error en el servidor" });
                }

                if (results.affectedRows === 0) {
                    return res.status(404).send({ message: "Usuario no encontrado" });
                }

                res.send({ message: "Contraseña restablecida con éxito" });
            }
        );
    } catch (error) {
        res.status(500).send({ message: "Error en el servidor" });
    }
});

// Servidor
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
