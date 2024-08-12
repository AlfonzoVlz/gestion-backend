import { body } from 'express-validator';

// Middleware de validación para el registro
export const validateRegistration = [
    body('nombre').notEmpty().withMessage('Nombre es requerido'),
    body('email').isEmail().withMessage('Email inválido'),
    body('contraseña').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres'),
    body('tipo').notEmpty().withMessage('Tipo es requerido'),
    body('apartamento').optional().isString().withMessage('Apartamento debe ser una cadena'),
    body('piso').optional().isInt().withMessage('Piso debe ser un número entero')
];

// Middleware de validación para el login
export const validateLogin = [
    body('email').isEmail().withMessage('Email inválido'),
    body('contraseña').notEmpty().withMessage('Contraseña es requerida')
];
