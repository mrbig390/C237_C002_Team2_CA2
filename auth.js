// austin - 25005454: user and admin login/registration module.
const express = require('express');
const crypto = require('crypto');
const { promisify } = require('util');

const scrypt = promisify(crypto.scrypt);

async function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const derivedKey = await scrypt(password, salt, 64);
    return `scrypt:${salt}:${derivedKey.toString('hex')}`;
}

async function verifyPassword(password, storedHash) {
    const [algorithm, salt, keyHex] = String(storedHash || '').split(':');
    if (algorithm !== 'scrypt' || !salt || !keyHex) return false;

    const storedKey = Buffer.from(keyHex, 'hex');
    const derivedKey = await scrypt(password, salt, storedKey.length);
    return storedKey.length === derivedKey.length && crypto.timingSafeEqual(storedKey, derivedKey);
}

function normaliseRole(role) {
    return role === 'admin' ? 'admin' : 'user';
}

function redirectFor(role) {
    return role === 'admin' ? '/admin' : '/user/dashboard';
}

function requireRole(role) {
    return (req, res, next) => {
        const user = req.session && req.session.authUser;
        if (!user) return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl)}`);
        if (user.role !== role) return res.status(403).send('Access denied');
        next();
    };
}

function createAuthRouter(db) {
    const router = express.Router();

    router.get('/login', (req, res) => {
        if (req.session.authUser) return res.redirect(redirectFor(req.session.authUser.role));
        res.render('auth/login', { error: null, values: { email: '', role: 'user' } });
    });

    router.post('/login', async (req, res) => {
        const email = String(req.body.email || '').trim().toLowerCase();
        const password = String(req.body.password || '');
        const role = normaliseRole(req.body.role);
        const values = { email, role };

        try {
            const [rows] = await db.query(
                'SELECT id, name, email, password_hash, role FROM users WHERE email = ? LIMIT 1',
                [email]
            );
            const user = rows[0];
            const valid = user && user.role === role && await verifyPassword(password, user.password_hash);
            if (!valid) {
                return res.status(401).render('auth/login', {
                    error: 'Incorrect email, password, or account type.', values
                });
            }

            req.session.regenerate(err => {
                if (err) return res.status(500).send('Unable to start login session');
                req.session.authUser = { id: user.id, name: user.name, email: user.email, role: user.role };
                res.redirect(redirectFor(user.role));
            });
        } catch (err) {
            console.error('Login error:', err.message);
            res.status(500).render('auth/login', { error: 'Unable to log in right now.', values });
        }
    });

    router.get('/register', (req, res) => {
        if (req.session.authUser) return res.redirect(redirectFor(req.session.authUser.role));
        res.render('auth/register', { error: null, values: { name: '', email: '', role: 'user' } });
    });

    router.post('/register', async (req, res) => {
        const name = String(req.body.name || '').trim();
        const email = String(req.body.email || '').trim().toLowerCase();
        const password = String(req.body.password || '');
        const confirmPassword = String(req.body.confirmPassword || '');
        const role = normaliseRole(req.body.role);
        const values = { name, email, role };

        if (name.length < 2 || !/^\S+@\S+\.\S+$/.test(email)) {
            return res.status(400).render('auth/register', { error: 'Enter a valid name and email.', values });
        }
        if (password.length < 8) {
            return res.status(400).render('auth/register', { error: 'Password must have at least 8 characters.', values });
        }
        if (password !== confirmPassword) {
            return res.status(400).render('auth/register', { error: 'Passwords do not match.', values });
        }
        if (role === 'admin' && process.env.ADMIN_REGISTRATION_CODE &&
            req.body.adminCode !== process.env.ADMIN_REGISTRATION_CODE) {
            return res.status(403).render('auth/register', { error: 'Invalid admin registration code.', values });
        }

        try {
            const passwordHash = await hashPassword(password);
            const [result] = await db.query(
                'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)',
                [name, email, passwordHash, role]
            );
            req.session.regenerate(err => {
                if (err) return res.status(500).send('Unable to start login session');
                req.session.authUser = { id: result.insertId, name, email, role };
                res.redirect(redirectFor(role));
            });
        } catch (err) {
            if (err.code === 'ER_DUP_ENTRY') {
                return res.status(409).render('auth/register', { error: 'An account already uses this email.', values });
            }
            console.error('Registration error:', err.message);
            res.status(500).render('auth/register', { error: 'Unable to register right now.', values });
        }
    });

    router.post('/logout', (req, res) => {
        req.session.destroy(() => res.redirect('/login'));
    });

    return router;
}

module.exports = { createAuthRouter, hashPassword, verifyPassword, requireRole };
// austin - 25005454: end user and admin login/registration module.
