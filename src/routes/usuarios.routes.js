import express from 'express';
import { validateLogin, validateRegistration } from '../middlewares/validation.middleware.js';
import { getUserData, login, registro } from '../controllers/usuarios.controller.js';
import { verifyToken } from '../middlewares/jwt.middleware.js';

const router = express.Router();

router.post('/registro', validateRegistration, registro)
router.post('/login', validateLogin, login)
router.get('/', verifyToken, getUserData)

export default router;