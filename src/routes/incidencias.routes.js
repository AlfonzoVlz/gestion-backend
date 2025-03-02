import express from 'express';
import { allIncidencias, createIncidencia, deleteIncidencia, IncidenciaById, IncidenciasByEstado, updateIncidencia, updateIncidenciaEstado } from '../controllers/incidencias.controller.js';
import { verifyToken } from '../middlewares/jwt.middleware.js';
import upload from '../middlewares/multer.middleware.js';

const router = express.Router();

router.post('/', verifyToken, upload.array('imagenes', 5), createIncidencia);
router.get('/', verifyToken, allIncidencias);
router.get('/:id', verifyToken, IncidenciaById);
router.get('/estado/:estado', verifyToken, IncidenciasByEstado );
router.put('/:id', verifyToken, upload.array('imagenes', 5), updateIncidencia);
router.put('/:id/estado', verifyToken, updateIncidenciaEstado);
router.delete('/:id', verifyToken, deleteIncidencia);

export default router;  
 