
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { promisify } = require('util');

const scrypt = promisify(crypto.scrypt);

async function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const key = await scrypt(password, salt, 64);
    return `scrypt:${salt}:${key.toString('hex')}`;
}

async function verifyPassword(password, storedHash = '') {
    if (storedHash.startsWith('$2')) return bcrypt.compare(password, storedHash);

    const [algorithm, salt, savedKey] = storedHash.split(':');
    if (algorithm !== 'scrypt' || !salt || !savedKey) return false;

    const key = await scrypt(password, salt, 64);
    const savedBuffer = Buffer.from(savedKey, 'hex');
    return savedBuffer.length === key.length && crypto.timingSafeEqual(savedBuffer, key);
}

function createAuth(db) {
    const router = express.Router();

    const sessionMiddleware = session({
        secret: process.env.SESSION_SECRET || 'change-this-session-secret-in-production',
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: 'lax',
            secure: process.env.NODE_ENV === 'production'
        }
    });


    router.get('/register', (req, res) => {
        res.render('auth/register', { error: null, values: {} });
    });

    router.post('/register', async (req, res) => {
        const name = String(req.body.name || '').trim();
        const email = String(req.body.email || '').trim().toLowerCase();
        const password = String(req.body.password || '');
        const role = req.body.role === 'admin' ? 'admin' : 'user';
        const values = { name, email, role };

        if (!name || !email || password.length < 8) {
            return res.status(400).render('auth/register', {
                error: 'Enter a name, a valid email, and a password of at least 8 characters.',
                values
            });
        }

        if (
            role === 'admin' &&
            (!process.env.ADMIN_REGISTRATION_CODE ||
                req.body.adminCode !== process.env.ADMIN_REGISTRATION_CODE)
        ) {
            return res.status(403).render('auth/register', {
                error: 'The admin registration code is invalid.',
                values
            });
        }

        try {
            const passwordHash = await hashPassword(password);

            await db.query(
                'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)',
                [name, email, passwordHash, role]
            );

            res.redirect('/login');
        } catch (error) {
            const duplicateEmail = error.code === 'ER_DUP_ENTRY';
            console.error('Registration error:', error.message);

            res.status(duplicateEmail ? 409 : 500).render('auth/register', {
                error: duplicateEmail
                    ? 'An account with that email already exists.'
                    : 'Unable to create the account.',
                values
            });
        }
    });


    router.get('/login', (req, res) => {
        res.render('auth/login', { error: null, email: '' });
    });

    router.post('/login', async (req, res) => {
        const email = String(req.body.email || '').trim().toLowerCase();
        const password = String(req.body.password || '');

        try {
            const [rows] = await db.query(
                'SELECT id, name, email, password_hash, role FROM users WHERE email = ? LIMIT 1',
                [email]
            );

            const user = rows[0];
            const validPassword = user && await verifyPassword(password, user.password_hash);

            if (!validPassword) {
                return res.status(401).render('auth/login', {
                    error: 'Invalid email or password.',
                    email
                });
            }

            req.session.regenerate(error => {
                if (error) return res.status(500).send('Unable to start session');

                req.session.user = {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                };

                res.redirect(user.role === 'admin' ? '/admin' : '/customer/tables');
            });
        } catch (error) {
            console.error('Login error:', error.message);
            res.status(500).render('auth/login', {
                error: 'Unable to log in.',
                email
            });
        }
    });

    return { router, sessionMiddleware };
}

module.exports = { createAuth, hashPassword, verifyPassword };
