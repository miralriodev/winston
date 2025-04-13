const express = require('express');
const router = express.Router();
const { admin, db } = require('../config/firebase');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const { body, validationResult } = require('express-validator');

// Solicitar restablecimiento de contraseña
router.post('/request-reset', [
    body('email').isEmail().withMessage('Por favor ingrese un email válido')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email } = req.body;
    try {
        // Buscar usuario por email
        const usersSnapshot = await db.collection('usersLog').where('email', '==', email).get();
        if (usersSnapshot.empty) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        const userDoc = usersSnapshot.docs[0];
        const userData = userDoc.data();

        // Verificar que el usuario tenga un secreto MFA configurado
        if (!userData.mfaSecret) {
            return res.status(400).json({ message: 'Usuario no tiene autenticación de dos factores configurada' });
        }

        // No generamos un nuevo token, el usuario debe usar su aplicación de autenticación

        // No necesitamos almacenar el token, ya que usaremos el código de la aplicación de autenticación
        res.status(200).json({
            message: 'Por favor ingrese el código de su aplicación de autenticación'
        });
    } catch (error) {
        console.error('Error al solicitar restablecimiento:', error);
        res.status(500).json({ message: 'Error al procesar la solicitud' });
    }
});

// Verificar código y restablecer contraseña
router.post('/reset', [
    body('email').isEmail().withMessage('Por favor ingrese un email válido'),
    body('token').not().isEmpty().withMessage('El código de verificación es requerido'),
    body('newPassword')
        .isLength({ min: 6 })
        .withMessage('La nueva contraseña debe tener al menos 6 caracteres')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, token, newPassword } = req.body;
    try {
        // Buscar usuario por email
        const usersSnapshot = await db.collection('usersLog').where('email', '==', email).get();
        if (usersSnapshot.empty) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        const userDoc = usersSnapshot.docs[0];
        const userData = userDoc.data();

        // Verificar que el usuario tenga un secreto MFA configurado
        if (!userData.mfaSecret) {
            return res.status(400).json({ message: 'Usuario no tiene autenticación de dos factores configurada' });
        }

        // Verificar el código TOTP
        const isValidToken = speakeasy.totp.verify({
            secret: userData.mfaSecret,
            encoding: 'base32',
            token: token,
            window: 1 // Permite una ventana de 30 segundos antes/después
        });

        if (!isValidToken) {
            return res.status(401).json({ message: 'Código de verificación inválido' });
        }

        // Actualizar contraseña
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        await db.collection('usersLog').doc(userDoc.id).update({
            password: hashedPassword
        });

        // Marcar el token como usado
        await db.collection('passwordResets').doc(email).update({
            used: true
        });

        res.status(200).json({ message: 'Contraseña actualizada exitosamente' });
    } catch (error) {
        console.error('Error al restablecer contraseña:', error);
        res.status(500).json({ message: 'Error al restablecer la contraseña' });
    }
});

module.exports = router;