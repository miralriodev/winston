// ===== IMPORTS =====
// Core dependencies
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');

// Configuration imports
const { admin, db } = require('./config/firebase');
const routes = require('./routes/route');
const passwordResetRoutes = require('./routes/password-reset');

// Logging
const winston = require('winston');

// Security
const rateLimit = require('express-rate-limit');

// ===== CONFIGURATION =====
// Load environment variables
dotenv.config();

// Constants
const PORT = process.env.PORT || 3002;
const JWT_SECRET = process.env.JWT_SECRET || 'miralhu';
const SERVER_ID = 1;

// ===== MIDDLEWARE SETUP =====
// Rate limiting configuration
const limiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 100, // Limit each IP to 100 requests per window
    message: 'Too many requests from this IP, please try again after an hour.'
});

// Logger configuration
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    defaultMeta: { service: 'user-service' },
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'all.log', level: 'info' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console()
    ]
});

// ===== EXPRESS APP SETUP =====
const app = express();

// Apply global middleware
app.use(cors());
app.use(bodyParser.json());
app.use(limiter);

// ===== CUSTOM MIDDLEWARE =====
// Request logging middleware
const requestLogger = (req, res, next) => {
    console.log(`[${req.method}] ${req.url} - Body:`, req.body);
    const startTime = Date.now();

    const originalSend = res.send;
    let statusCode;

    res.send = function (body) {
        statusCode = res.statusCode;
        originalSend.call(this, body);
    };

    res.on('finish', async () => {
        const logLevel = res.statusCode >= 400 ? 'error' : 'info';
        const responseTime = Date.now() - startTime;
        const logData = {
            logLevel,
            timestamp: admin.firestore.Timestamp.fromDate(new Date()),
            method: req.method,
            url: req.url,
            path: req.path,
            query: req.query || {},
            params: req.params || {},
            status: Number(statusCode || res.statusCode),
            responseTime: Number(responseTime),
            body: req.body,
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.get('user-agent'),
            protocol: req.protocol,
            hostname: req.hostname,
            serverId: Number(SERVER_ID),
            system: {
                nodeVersion: process.version,
                environment: process.env.NODE_ENV || 'development',
                pid: Number(process.pid),
                memoryUsage: {
                    heapTotal: Number(process.memoryUsage().heapTotal),
                    heapUsed: Number(process.memoryUsage().heapUsed),
                    external: Number(process.memoryUsage().external),
                    rss: Number(process.memoryUsage().rss),
                    arrayBuffers: Number(process.memoryUsage().arrayBuffers || 0)
                }
            }
        };
        
        // logger.log(logLevel, 'Request completed', logData);

        try {
            await db.collection('logs').add(logData);   
        } catch (error) {
            logger.error('Failed to log request', error);
        }
    });

    next();
};

// JWT verification middleware
const verifyToken = (req, res, next) => {
    const token = req.headers['x-access-token'];
    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Failed to authenticate token' });
        }
        req.username = decoded.username;
        next();
    });
};

// Apply custom middleware
app.use(requestLogger);

// ===== ROUTES =====
// API routes
app.use('/api', routes);
app.use('/api/', passwordResetRoutes);


// ===== ERROR HANDLING =====
// 404 handler
app.use((req, res, next) => {
    res.status(404).json({ message: 'Route not found' });
});

// Global error handler
app.use((err, req, res, next) => {
    logger.error('Unhandled error', { error: err.message, stack: err.stack });
    res.status(500).json({ message: 'Internal server error' });
});

// ===== SERVER INITIALIZATION =====
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// For testing/module exports
module.exports = app;

// Modificar la configuración CORS para permitir solicitudes desde cualquier origen en producción
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://tu-frontend-app.onrender.com', 'http://localhost:3000'] 
    : 'http://localhost:3000',
  credentials: true
}));