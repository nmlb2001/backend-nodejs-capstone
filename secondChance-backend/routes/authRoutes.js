const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const connectToDatabase = require('../models/db');
const router = express.Router();
const dotenv = require('dotenv');
const pino = require('pino');  // Importar el registrador Pino
//Tarea 1: Usar `body`, `validationResult` de `express-validator` para la validación de entrada
const { body, validationResult } = require('express-validator');
const logger = pino();  // Crear una instancia del registrador Pino
dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET;
router.post('/register', async (req, res) => {
    try {
      //Conectar a `secondChance` en MongoDB a través de `connectToDatabase` en `db.js`.
      const db = await connectToDatabase();
      const collection = db.collection("users");
      const existingEmail = await collection.findOne({ email: req.body.email });
        if (existingEmail) {
            logger.error('El id de correo electrónico ya existe');
            return res.status(400).json({ error: 'El id de correo electrónico ya existe' });
        }
        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);
        const email=req.body.email;
        console.log('el correo es',email);
        const newUser = await collection.insertOne({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        });
        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };
        const authtoken = jwt.sign(payload, JWT_SECRET);
        logger.info('Usuario registrado con éxito');
        res.json({ authtoken,email });
    } catch (e) {
        logger.error(e);
        return res.status(500).send('Error interno del servidor');
    }
});
router.post('/login', async (req, res) => {
    console.log("\n\n Dentro del inicio de sesión")
    try {
        // const collection = await connectToDatabase();
        const db = await connectToDatabase();
        const collection = db.collection("users");
        const theUser = await collection.findOne({ email: req.body.email });
        if (theUser) {
            let result = await bcryptjs.compare(req.body.password, theUser.password)
            if(!result) {
                logger.error('Las contraseñas no coinciden');
                return res.status(404).json({ error: 'Contraseña incorrecta' });
            }
            let payload = {
                user: {
                    id: theUser._id.toString(),
                },
            };
            const userName = theUser.firstName;
            const userEmail = theUser.email;
            const authtoken = jwt.sign(payload, JWT_SECRET);
            logger.info('Usuario ha iniciado sesión con éxito');
            return res.status(200).json({ authtoken, userName, userEmail });
        } else {
            logger.error('Usuario no encontrado');
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
    } catch (e) {
        logger.error(e);
        return res.status(500).json({ error: 'Error interno del servidor', details: e.message });
      }
});
// API de actualización
router.put('/update', async (req, res) => {
    // Tarea 2: Validar la entrada usando `validationResult` y devolver un mensaje apropiado si hay un error.
    const errors = validationResult(req);
    // Tarea 3: Comprobar si `email` está presente en el encabezado y lanzar un mensaje de error apropiado si no está presente.
    if (!errors.isEmpty()) {
        logger.error('Errores de validación en la solicitud de actualización', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const email = req.headers.email;
        if (!email) {
            logger.error('Correo electrónico no encontrado en los encabezados de la solicitud');
            return res.status(400).json({ error: "Correo electrónico no encontrado en los encabezados de la solicitud" });
        }
        //Tarea 4: Conectar a MongoDB
        const db = await connectToDatabase();
        const collection = db.collection("users");
        //Tarea 5: Encontrar las credenciales del usuario
        const existingUser = await collection.findOne({ email });
        if (!existingUser) {
            logger.error('Usuario no encontrado');
            return res.status(404).json({ error: "Usuario no encontrado" });
        }
        existingUser.firstName = req.body.name;
        existingUser.updatedAt = new Date();
        //Tarea 6: Actualizar las credenciales del usuario en la base de datos
        const updatedUser = await collection.findOneAndUpdate(
            { email },
            { $set: existingUser },
            { returnDocument: 'after' }
        );
        //Tarea 7: Crear autenticación JWT con user._id como carga útil usando la clave secreta del archivo .env
        const payload = {
            user: {
                id: updatedUser._id.toString(),
            },
        };
        const authtoken = jwt.sign(payload, JWT_SECRET);
        logger.info('Usuario actualizado con éxito');
        res.json({ authtoken });
    } catch (error) {
        logger.error(error);
        return res.status(500).send("Error interno del servidor");
    }
});
module.exports = router;
