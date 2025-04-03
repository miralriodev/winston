const express = require('express')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const { admin, db } = require('../config/firebase')
const router = express.Router()
const JWT_SECRET = process.env.JWT_SECRET || 'miralhu'
const speakeasy = require('speakeasy')
const { body, validationResult } = require('express-validator')



// User registration with validation
router.post('/register', [
    body('email')
        .isEmail()
        .withMessage('Please enter a valid email')
        .normalizeEmail(),
    body('username')
        .not().isEmpty()
        .withMessage('Username is required')
        .trim(),
    body('password')
        .not().isEmpty()
        .withMessage('Password is required')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters long')
], async (req, res) => {
    // Check for validation errors
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }

    const { username, password, email } = req.body
    try {
        const userDoc = await db.collection('usersLog').doc(username).get()
        if (userDoc.exists) {
            return res.status(400).json({ message: 'Username already exists' })
        }

        const emailQuery = await db.collection('usersLog').where('email', '==', email).get()
        if (!emailQuery.empty) {
            return res.status(400).json({ message: 'Email already in use' })
        }

        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password, salt)
        const secret = speakeasy.generateSecret({
            name: `Miral:${email}`, // Formato correcto: servicio:cuenta
            length: 32
        });

        await db.collection('usersLog').doc(username).set({
            email,
            username,
            password: hashedPassword,
            mfaSecret: secret.base32
        })
        res.status(201).json({
            message: 'User registered successfully',
            secretUrl: secret.otpauth_url
        })
    } catch (error) {
        console.error('Registration error:', error)
        res.status(500).json({ message: 'Failed to register user' })
    }
})

//user login
router.post('/login', [
    // Añadir validación de campos
    body('username').not().isEmpty().withMessage('Email is required'),
    body('password').not().isEmpty().withMessage('Password is required')
], async (req, res) => {
    // Validar campos
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }

    const { username, password } = req.body
    try {
        const user = await db.collection('usersLog').doc(username).get()
        if (user.exists) {
            const validPassword = await bcrypt.compare(password, user.data().password)
            if (validPassword) {
                // Generar token temporal para la fase MFA
                const tempToken = jwt.sign(
                    { username, requiresMFA: true },
                    JWT_SECRET,
                    { expiresIn: '5m' }
                )

                // Responder con información para la siguiente fase de autenticación (MFA)
                res.status(200).json({
                    message: 'First authentication step successful',
                    requiresMFA: true,
                    tempToken,
                    mfaIdentifier: user.data().email // Usar email para la verificación OTP
                })
            } else {
                res.status(401).json({ message: 'Invalid password' })
            }
        } else {
            res.status(404).json({ message: 'User not found' })
        }
    } catch (error) {
        console.error('Login error:', error)
        res.status(500).json({ message: 'Failed to login user' })
    }
})

router.post('/verify-otp', async (req, res) => {
    const { username, token } = req.body
    try {
        const user = await db.collection('usersLog').doc(username).get()
        if (!user.exists) {
            return res.status(404).json({ message: 'User not found' })
        }
        const verified = speakeasy.totp.verify({
            secret: user.data().mfaSecret,
            encoding: 'base32',
            token,
            window: 1
        })

        if (verified) {
            res.status(200).json({ success: true })
        } else {
            res.status(401).json({ success: false })
        }
    } catch (error) {
        console.error('Verfication error:', error)
        res.status(500).json({
            success: false,
            message: 'Server error during verification'
        })

    }

})

router.get('/getInfo', (req, res) => {
    res.status(200).json({
        nodeVersion: process.version,
        student: {
            fullName: "Hugo Alberto Miralrio Espinoza",
            group: "IDGS11"
        }
    });
});

// Enhanced logs endpoint
router.get('/logs', async (req, res) => {
  try {
    const logsSnapshot = await db.collection('logs').get();
    const logs = [];
    
    logsSnapshot.forEach(doc => {
      const data = doc.data();
      logs.push({
        id: doc.id,
        timestamp: data.timestamp,
        method: data.method,
        path: data.path,
        status: data.status,
        responseTime: data.responseTime,
        serverId: data.serverId || 1,
        logLevel: data.logLevel,
        ip: data.ip,
        userAgent: data.userAgent,
        protocol: data.protocol,
        memoryUsage: data.system?.memoryUsage || {},
        environment: data.system?.environment,
        body: data.body,
        query: data.query
      });
    });

    // Sort by timestamp (most recent first)
    logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    res.status(200).json(logs);
  } catch (error) {
    console.error('Error fetching logs:', error);
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

module.exports = router;