import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { pool } from '../config/db.js';
import { DB_SECRET_KEY } from '../config/config.js';
import { validationResult } from 'express-validator';
import { validateRegistration, validateLogin } from '../middlewares/validation.middleware.js';

export const registro = async (req, res) => {
    // Validar la entrada
    await Promise.all(validateRegistration.map(validator => validator.run(req)));
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { nombre, email, contraseña, tipo, apartamento, piso } = req.body;

        // Verificar que todos los campos requeridos están definidos
        if (nombre === undefined || email === undefined || contraseña === undefined || tipo === undefined || apartamento === undefined || piso === undefined) {
            return res.status(400).json({ message: 'Faltan campos requeridos' });
        }

        // Hashear la contraseña para seguridad
        const hashedPassword = await bcrypt.hash(contraseña, 10);

        // Insertar el usuario en la base de datos
        const [result] = await pool.execute(
            'INSERT INTO users (nombre, email, contraseña, tipo, apartamento, piso) VALUES (?, ?, ?, ?, ?, ?)', 
            [nombre, email, hashedPassword, tipo, apartamento, piso]
        );

        // Enviar una respuesta exitosa con el ID del nuevo usuario
        res.status(201).json({ message: 'Usuario registrado exitosamente', userId: result.insertId });
    } catch (error) {
        // Loguear el error y responder con un mensaje genérico
        console.error('Error al registrar usuario:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
}

// Controlador de login
export const login = async (req, res) => {
    // Validar la entrada
    await Promise.all(validateLogin.map(validator => validator.run(req)));
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { email, contraseña } = req.body;
        
        const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);

        if (users.length === 0) {
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }

        const user = users[0];
        const isMatch = await bcrypt.compare(contraseña, user.contraseña);

        if (!isMatch) {
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }

        const token = jwt.sign({ id: user.id }, DB_SECRET_KEY, { expiresIn: '1d' });
        res.json({ token, user: { id: user.id, nombre: user.nombre, tipo: user.tipo, piso: user.piso } });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
}

export const getUserData = async (req, res) => {
    try {
      const userId = req.user.id; // Asegúrate de que el ID del usuario esté en req.user
      const [users] = await pool.execute('SELECT id, nombre, email, tipo, apartamento, piso FROM users WHERE id = ?', [userId]);
  
      if (users.length === 0) {
        return res.status(404).json({ message: 'Usuario no encontrado' });
      }
  
      res.json(users[0]);
    } catch (error) {
      console.error('Error al obtener datos del usuario:', error);
      res.status(500).json({ message: 'Error interno del servidor' });
    }
  };

