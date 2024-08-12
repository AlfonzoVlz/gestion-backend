import jwt from 'jsonwebtoken';
import { DB_SECRET_KEY } from '../config/config.js';

export const verifyToken = (req, res, next) => {
  console.log('Iniciando verificación de token');

  try {
    // Verificar que el header de autorización esté presente
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.log('Header de autorización no presente o formato inválido');
      return res.status(401).json({ message: 'No se proporcionó token de autenticación' });
    }

    // Extraer el token del header
    const token = authHeader.split(' ')[1];

    // Verificar el token usando jwt.verify
    const decoded = jwt.verify(token, DB_SECRET_KEY);
    req.user = decoded; // Asignar el payload decodificado a req.user

    next(); // Continuar con el siguiente middleware o ruta

  } catch (error) {
    console.error('Error en la verificación del token:', error);
    
    // Manejar errores específicos de JWT
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expirado' });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Token inválido' });
    }
    
    // Manejar cualquier otro error general
    res.status(401).json({ message: 'Autenticación fallida', error: error.message });
  }
};
