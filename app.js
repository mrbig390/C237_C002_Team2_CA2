const express = require('express');
const mysql = require('mysql2/promise');
const app = express();
const session = require('express-session');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const db = mysql.createPool({
    host: process.env.DB_HOST || 'c237-marlina-mysql.mysql.database.azure.com',
    user: process.env.DB_USER || 'c237_002',
    password: process.env.DB_PASS || 'c237002@2026!',
    database: process.env.DB_NAME || 'c237_002_team2_restaurant_reservation_system',
    ssl: { rejectUnauthorized: true },
    // ponytail: dates come back as 'YYYY-MM-DD' strings, so views print them raw.
    // Without this, mysql2 returns local-midnight Date objects and toISOString() shifts a day.
    dateStrings: true
});

// austin - 25005454: user and admin login/registration functions.
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

function createAuthRouter(dbConnection) {
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
            const [rows] = await dbConnection.query(
                'SELECT id, name, email, password_hash, role FROM users WHERE email = ? LIMIT 1', [email]
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
                req.session.authUser = {
                    id: user.id, name: user.name, email: user.email, role: user.role
                };
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
            return res.status(400).render('auth/register', {
                error: 'Password must have at least 8 characters.', values
            });
        }
        if (password !== confirmPassword) {
            return res.status(400).render('auth/register', { error: 'Passwords do not match.', values });
        }
        if (role === 'admin' && process.env.ADMIN_REGISTRATION_CODE &&
            req.body.adminCode !== process.env.ADMIN_REGISTRATION_CODE) {
            return res.status(403).render('auth/register', {
                error: 'Invalid admin registration code.', values
            });
        }

        try {
            const passwordHash = await hashPassword(password);
            const [result] = await dbConnection.query(
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
                return res.status(409).render('auth/register', {
                    error: 'An account already uses this email.', values
                });
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


app.set('view engine', 'ejs');
app.use(express.static('public'));

app.use(express.urlencoded({ extended: false }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'change-this-session-secret-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' }
}));


// DEV ONLY — remove on integration. Fakes a logged-in admin so pages render.
// Replace with the real requireAdmin middleware from the auth slice.
app.use((req, res, next) => {
    req.session = req.session || {};
    req.session.user = { id: 1, name: 'Site Admin', role: 'admin' };
    res.locals.currentUser = req.session.user;
    // ponytail: badge helper is a lookup, not a partial.
    res.locals.badge = {
        pending: 'warning',
        confirmed: 'success',
        rejected: 'danger',
        cancelled: 'secondary'
    };
    next();
});


app.use(createAuthRouter(db));
app.use((req, res, next) => {
    req.session.user = req.session.authUser || null;
    res.locals.currentUser = req.session.user;
    next();
});
app.use('/admin', requireRole('admin'));
app.use('/user', requireRole('user'));


// ponytail: two optional filters, so a two-branch builder. Generalize if a third arrives.
function buildFilter({ status, date }) {
    const where = [], params = [];
    if (status) { where.push('r.status = ?'); params.push(status); }
    if (date) { where.push('r.reservation_date = ?'); params.push(date); }
    return { clause: where.length ? ' WHERE ' + where.join(' AND ') : '', params };
}

app.get('/', (req, res) => res.redirect('/admin'));

app.get('/admin', async (req, res) => {
    try {
        const [[byStatus], [[totals]], [upcoming]] = await Promise.all([
            db.query('SELECT status, COUNT(*) AS n FROM reservations GROUP BY status'),
            db.query(`SELECT (SELECT COUNT(*) FROM restaurant_tables) AS tables,
                             (SELECT COUNT(*) FROM users)             AS users`),
            db.query(`SELECT r.id, u.name AS customer_name, t.table_number,
                             r.reservation_date, r.time_slot, r.status
                      FROM reservations r
                      JOIN users u             ON u.id = r.user_id
                      JOIN restaurant_tables t ON t.id = r.table_id
                      WHERE r.reservation_date >= CURDATE()
                        AND r.status IN ('pending','confirmed')
                      ORDER BY r.reservation_date, r.time_slot
                      LIMIT 10`)
        ]);
        const counts = Object.fromEntries(byStatus.map(r => [r.status, r.n]));
        res.render('admin/dashboard', {
            counts,
            totalReservations: byStatus.reduce((sum, r) => sum + r.n, 0),
            totals,
            upcoming
        });
    } catch (err) {
        console.error('Dashboard query error:', err.message);
        res.status(500).send('Error loading dashboard');
    }
});

app.get('/admin/reservations', async (req, res) => {
    const { clause, params } = buildFilter(req.query);
    try {
        const [rows] = await db.query(
            `SELECT r.id,
                    u.name  AS customer_name,
                    u.email AS customer_email,
                    t.table_number,
                    r.reservation_date,
                    r.time_slot,
                    r.party_size,
                    r.remarks,
                    r.status
             FROM reservations r
             JOIN users u             ON u.id = r.user_id
             JOIN restaurant_tables t ON t.id = r.table_id${clause}
             ORDER BY r.id DESC`,
            params
        );
        res.render('admin/reservations', { rows, filter: req.query });
    } catch (err) {
        console.error('Reservations query error:', err.message);
        res.status(500).send('Error loading reservations');
    }
});

app.get('/admin/tables', async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT id, table_number, capacity, location FROM restaurant_tables ORDER BY table_number'
        );
        res.render('admin/tables', { rows });
    } catch (err) {
        console.error('Tables query error:', err.message);
        res.status(500).send('Error loading tables');
    }
});

app.get('/admin/users', async (req, res) => {
    try {
        // Never select password_hash.
        const [rows] = await db.query(
            'SELECT id, name, email, role, created_at FROM users ORDER BY id'
        );
        res.render('admin/users', { rows });
    } catch (err) {
        console.error('Users query error:', err.message);
        res.status(500).send('Error loading users');
    }
});


//chu fon
app.get('/user/dashboard', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const [myReservations] = await db.query(
            `SELECT r.id, t.table_number
            FROM reservations r
            JOIN restaurant_tables t ON t.id = r.table_id
            WHERE r.user_id = ? 
            ORDER BY r.reservation_date DESC, r.time_slot DESC`,
            [userId]
        );

        const [availableTables] = await db.query(
            `SELECT id, table_number, capacity, location
            FROM restaurant_tables ORDER BY table_number`
        );
        
        res.render('user/dashboard', { myReservations, availableTables });
    } catch (err) {
        console.error('User dashboard query error:', err.message);
        res.status(500).send('Error loading user dashboard');
    }
});


app.get('/user/reservations', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const reservationsId = req.params.id;

        // Get the reservation (make sure it belongs to this user)
        const [reservation] = await db.query(
            `SELECT r.*, t.table_number 
             FROM reservations r
             JOIN restaurant_tables t ON t.id = r.table_id
             WHERE r.id = ? AND r.user_id = ?`,
            [reservationId, userId]
        );

        if (reservation.length === 0) {
            return res.status(404).send('Reservation not found');
        }

        // Get available tables for the dropdown
        const [availableTables] = await db.query(
            'SELECT id, table_number, capacity FROM restaurant_tables ORDER BY table_number'
        );

        res.render('user/reservations', {
            reservation: reservation[0],
            availableTables,
            title: 'Edit Reservation'
        });
    } catch (err) {
        console.error('User reservations query error:', err.message);
        res.status(500).send('Error loading edit form');
    }
});

// Create new reservation
app.post('/user/reservations', async (req, res) => {
    const { table_id, party_size, reservation_date, time_slot, remarks } = req.body;
    const userId = req.session.user.id;

    try {
        // Check if table is already booked for this time slot
        const [existing] = await db.query(
            `SELECT id FROM reservations 
             WHERE table_id = ? AND reservation_date = ? AND time_slot = ? 
             AND status IN ('pending', 'confirmed')`,
            [table_id, reservation_date, time_slot]
        );

        if (existing.length > 0) {
            return res.status(400).send('Table is already booked for this time slot');
        }

        // Create the reservation
        await db.query(
            `INSERT INTO reservations (user_id, table_id, party_size, reservation_date, time_slot, remarks, status) 
             VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
            [userId, table_id, party_size, reservation_date, time_slot, remarks]
        );

        res.redirect('/user/dashboard');
    } catch (err) {
        console.error('Create reservation error:', err.message);
        res.status(500).send('Error creating reservation');
    }
});

// Update reservation
app.post('/user/reservations/:id/update', async (req, res) => {
    const { table_id, party_size, reservation_date, time_slot, remarks } = req.body;
    const reservationId = req.params.id;
    const userId = req.session.user.id;

    try {
        await db.query(
            `UPDATE reservations 
             SET table_id = ?, party_size = ?, reservation_date = ?, time_slot = ?, remarks = ?
             WHERE id = ? AND user_id = ? AND status = 'pending'`,
            [table_id, party_size, reservation_date, time_slot, remarks, reservationId, userId]
        );

        res.redirect('/user/dashboard');
    } catch (err) {
        console.error('Update reservation error:', err.message);
        res.status(500).send('Error updating reservation');
    }
});

// Delete/Cancel reservation (using POST for simplicity, or use DELETE method)
app.post('/user/reservations/:id/delete', async (req, res) => {
    const reservationId = req.params.id;
    const userId = req.session.user.id;

    try {
        // Check if reservation belongs to user and is pending
        const [reservation] = await db.query(
            'SELECT status FROM reservations WHERE id = ? AND user_id = ?',
            [reservationId, userId]
        );

        if (reservation.length === 0) {
            return res.status(404).send('Reservation not found');
        }

        if (reservation[0].status !== 'pending') {
            return res.status(400).send('Cannot cancel a confirmed reservation');
        }

        // Update status to cancelled instead of deleting
        await db.query(
            'UPDATE reservations SET status = "cancelled" WHERE id = ? AND user_id = ?',
            [reservationId, userId]
        );

        res.redirect('/user/dashboard');
    } catch (err) {
        console.error('Cancel reservation error:', err.message);
        res.status(500).send('Error cancelling reservation');
    }
});

// end chu fon



const PORT = process.env.PORT || 3000;
if (require.main === module) {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = { app, buildFilter };
