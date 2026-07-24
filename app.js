// austin - 25005454: auth logic merged in from auth.js so the app is one file.
const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const crypto = require('crypto');
const flash = require('connect-flash');
const multer = require('multer');
const fs = require('fs');

const app = express();

// FIX: multer.diskStorage does not create its destination folder — it just errors on
// the first upload if 'public/images' doesn't exist yet. Created up front so a fresh
// checkout works immediately.
fs.mkdirSync('public/images', { recursive: true });

// Set up multer for table-picture uploads, same pattern as L18 (Image Upload).
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/images');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

// Database connection
const db = mysql.createConnection({
    host: 'c237-marlina-mysql.mysql.database.azure.com',
    user: 'c237_002',
    password: 'c237002@2026!',
    database: 'c237_002_team2_restaurant_reservation_system',
    ssl: {
        rejectUnauthorized: true
    },
    dateStrings: true
}).promise();

// createConnection opens one connection and, unlike a pool, an unhandled connection
// error kills the whole Node process. This logs it instead so the app stays up if the
// database blips.
db.connection.on('error', (err) => console.error('Database connection error:', err.code));

// Code someone must type to register an admin account. Fixed value so the app works
// straight from a checkout with no environment variable to set.
const ADMIN_REGISTRATION_CODE = 'admin';

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-super-secret-key-change-this',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

app.use(flash());

// ===== AUTH HELPERS =====
function hashPassword(password) {
    return crypto.createHash('sha1').update(String(password)).digest('hex');
}

function verifyPassword(password, storedHash) {
    if (!storedHash) return false;
    return hashPassword(password) === String(storedHash);
}

function normaliseRole(role) {
    return role === 'admin' ? 'admin' : 'user';
}

function redirectFor(role) {
    return role === 'admin' ? '/admin' : '/user/dashboard';
}

function isPastDate(dateStr) {
    const today = new Date().toISOString().slice(0, 10);
    return String(dateStr) < today;
}

function requireRole(role) {
    return (req, res, next) => {
        const user = req.session && req.session.user;
        if (!user) return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl)}`);
        if (user.role !== role) return res.status(403).send('Access denied');
        next();
    };
}

app.use((req, res, next) => {
    res.locals.currentUser = req.session.user || null;
    res.locals.flashSuccess = req.flash('success');
    res.locals.flashError = req.flash('error');
    res.locals.badge = {
        pending: 'warning',
        confirmed: 'success',
        rejected: 'danger',
        cancelled: 'secondary'
    };
    next();
});

function buildFilter({ status, date, q }) {
    const where = [], params = [];
    if (status) { where.push('r.status = ?'); params.push(status); }
    if (date) { where.push('r.reservation_date = ?'); params.push(date); }
    const term = String(q || '').trim();
    if (term) {
        where.push('(u.name LIKE ? OR u.email LIKE ?)');
        params.push('%' + term + '%', '%' + term + '%');
    }
    return { clause: where.length ? ' WHERE ' + where.join(' AND ') : '', params };
}

const SORT_COLUMNS = {
    reservations: {
        id: 'r.id', customer: 'u.name', table: 't.table_number',
        date: 'r.reservation_date', slot: 'r.time_slot', party: 'r.party_size', status: 'r.status'
    },
    tables: { id: 'id', table_number: 'table_number', capacity: 'capacity', location: 'location' },
    users: { id: 'id', name: 'name', email: 'email', role: 'role', created_at: 'created_at' },
    myReservations: {
        table: 't.table_number', date: 'r.reservation_date',
        slot: 'r.time_slot', party: 'r.party_size', status: 'r.status'
    }
};

function buildSort(view, query, defaultCol, defaultDir = 'asc') {
    const cols = SORT_COLUMNS[view];
    const sort = cols[query.sort] ? query.sort : defaultCol;
    const dir = String(query.dir).toLowerCase() === 'desc' ? 'desc' : (defaultDir === 'desc' && !query.sort ? 'desc' : 'asc');
    return { orderBy: `ORDER BY ${cols[sort]} ${dir.toUpperCase()}`, sort, dir };
}

function sortLink(baseQuery, col, currentSort, currentDir) {
    const nextDir = currentSort === col && currentDir === 'asc' ? 'desc' : 'asc';
    const params = new URLSearchParams({ ...baseQuery, sort: col, dir: nextDir });
    return '?' + params.toString();
}

// Landing route
app.get('/', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    res.redirect(redirectFor(req.session.user.role));
});

// ============ AUTH ROUTES ============
app.get('/login', (req, res) => {
    if (req.session.user) return res.redirect(redirectFor(req.session.user.role));
    res.render('auth/login', { error: null, values: { email: '', role: 'user' } });
});

app.post('/login', async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const role = normaliseRole(req.body.role);
    const values = { email, role };

    try {
        const [rows] = await db.query(
            'SELECT id, name, email, role FROM users WHERE email = ? AND password_hash = SHA1(?) LIMIT 1',
            [email, password]
        );
        const user = rows[0];
        const valid = user && user.role === role;
        if (!valid) {
            return res.status(401).render('auth/login', {
                error: 'Incorrect email, password, or account type.', values
            });
        }

        req.session.regenerate(err => {
            if (err) return res.status(500).send('Unable to start login session');
            req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
            res.redirect(redirectFor(user.role));
        });
    } catch (err) {
        console.error('Login error:', err.message);
        res.status(500).render('auth/login', { error: 'Unable to log in right now.', values });
    }
});

app.get('/register', (req, res) => {
    if (req.session.user) return res.redirect(redirectFor(req.session.user.role));
    res.render('auth/register', { error: null, values: { name: '', email: '', role: 'user' } });
});

app.post('/register', async (req, res) => {
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
    if (role === 'admin' && req.body.adminCode !== ADMIN_REGISTRATION_CODE) {
        return res.status(403).render('auth/register', { error: 'Invalid admin registration code.', values });
    }

    try {
        const [result] = await db.query(
            'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, SHA1(?), ?)',
            [name, email, password, role]
        );
        req.session.regenerate(err => {
            if (err) return res.status(500).send('Unable to start login session');
            req.session.user = { id: result.insertId, name, email, role };
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

app.post('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
});

// ============ ADMIN ROUTES ============
app.get('/admin', requireRole('admin'), async (req, res) => {
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
        res.render('admin/admin_dashboard', {
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

app.get('/admin/reservations', requireRole('admin'), async (req, res) => {
    const { clause, params } = buildFilter(req.query);
    const { orderBy, sort, dir } = buildSort('reservations', req.query, 'id', 'desc');
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
                    r.status,
                    r.cancellation_reason
             FROM reservations r
             JOIN users u             ON u.id = r.user_id
             JOIN restaurant_tables t ON t.id = r.table_id${clause}
             ${orderBy}`,
            params
        );
        res.render('admin/admin_reservations', {
            rows, filter: req.query, sort, dir,
            sortLink: (col) => sortLink(req.query, col, sort, dir)
        });
    } catch (err) {
        console.error('Reservations query error:', err.message);
        res.status(500).send('Error loading reservations');
    }
});

app.post('/admin/reservations/:id/delete', requireRole('admin'), async (req, res) => {
    try {
        await db.query('DELETE FROM reservations WHERE id = ?', [req.params.id]);
        req.flash('success', `Reservation #${req.params.id} deleted.`);
        res.redirect('/admin/reservations');
    } catch (err) {
        console.error('Delete reservation error:', err.message);
        res.status(500).send('Error deleting reservation');
    }
});

app.get('/admin/tables', requireRole('admin'), async (req, res) => {
    const { orderBy, sort, dir } = buildSort('tables', req.query, 'table_number');
    try {
        const [rows] = await db.query(
            `SELECT id, table_number, capacity, location, image FROM restaurant_tables ${orderBy}`
        );
        res.render('admin/admin_tables', {
            rows, sort, dir,
            sortLink: (col) => sortLink(req.query, col, sort, dir)
        });
    } catch (err) {
        console.error('Tables query error:', err.message);
        res.status(500).send('Error loading tables');
    }
});

app.post('/admin/tables/:id/delete', requireRole('admin'), async (req, res) => {
    const tableId = req.params.id;
    try {
        const [[active]] = await db.query(
            `SELECT COUNT(*) AS n FROM reservations WHERE table_id = ? AND status IN ('pending','confirmed')`,
            [tableId]
        );
        if (active.n > 0) {
            req.flash('error', 'Cannot delete a table with active reservations. Resolve them first.');
            return res.redirect('/admin/tables');
        }
        await db.query('DELETE FROM restaurant_tables WHERE id = ?', [tableId]);
        req.flash('success', 'Table deleted.');
        res.redirect('/admin/tables');
    } catch (err) {
        console.error('Delete table error:', err.message);
        res.status(500).send('Error deleting table');
    }
});

app.get('/admin/users', requireRole('admin'), async (req, res) => {
    const { orderBy, sort, dir } = buildSort('users', req.query, 'id');
    try {
        const [rows] = await db.query(
            `SELECT id, name, email, role, created_at FROM users ${orderBy}`
        );
        res.render('admin/admin_users', {
            rows, sort, dir,
            sortLink: (col) => sortLink(req.query, col, sort, dir)
        });
    } catch (err) {
        console.error('Users query error:', err.message);
        res.status(500).send('Error loading users');
    }
});

app.post('/admin/users/:id/delete', requireRole('admin'), async (req, res) => {
    const userId = req.params.id;

    if (Number(userId) === req.session.user.id) {
        req.flash('error', 'You cannot delete your own account while logged in as it.');
        return res.redirect('/admin/users');
    }

    try {
        const [[target]] = await db.query('SELECT role FROM users WHERE id = ?', [userId]);
        if (!target) {
            req.flash('error', 'User not found.');
            return res.redirect('/admin/users');
        }

        if (target.role === 'admin') {
            const [[adminCount]] = await db.query(`SELECT COUNT(*) AS n FROM users WHERE role = 'admin'`);
            if (adminCount.n <= 1) {
                req.flash('error', 'Cannot delete the last remaining admin account.');
                return res.redirect('/admin/users');
            }
        }

        const [[active]] = await db.query(
            `SELECT COUNT(*) AS n FROM reservations WHERE user_id = ? AND status IN ('pending','confirmed')`,
            [userId]
        );
        if (active.n > 0) {
            req.flash('error', 'Cannot delete a user with active reservations. Resolve them first.');
            return res.redirect('/admin/users');
        }

        await db.query('DELETE FROM users WHERE id = ?', [userId]);
        req.flash('success', 'User deleted.');
        res.redirect('/admin/users');
    } catch (err) {
        console.error('Delete user error:', err.message);
        res.status(500).send('Error deleting user');
    }
});

// ============ ADMIN MANAGEMENT ============

const RESERVATION_STATUSES = ['pending', 'confirmed', 'rejected', 'cancelled'];
const LIVE_STATUSES = ['pending', 'confirmed'];

app.post('/admin/reservations/:id/status', requireRole('admin'), async (req, res) => {
    const reservationId = req.params.id;
    const status = String(req.body.status || '');
    const reason = ['rejected', 'cancelled'].includes(status)
        ? (String(req.body.reason || '').trim() || null)
        : null;

    if (!RESERVATION_STATUSES.includes(status)) {
        req.flash('error', 'Unknown reservation status.');
        return res.redirect('/admin/reservations');
    }

    try {
        const [[reservation]] = await db.query(
            'SELECT table_id, reservation_date, time_slot, status FROM reservations WHERE id = ?',
            [reservationId]
        );
        if (!reservation) {
            req.flash('error', 'Reservation not found.');
            return res.redirect('/admin/reservations');
        }
        if (reservation.status === status) {
            req.flash('error', `Reservation #${reservationId} is already ${status}.`);
            return res.redirect('/admin/reservations');
        }

        if (LIVE_STATUSES.includes(status)) {
            const [clash] = await db.query(
                `SELECT id FROM reservations
                 WHERE table_id = ? AND reservation_date = ? AND time_slot = ?
                   AND status IN ('pending','confirmed') AND id != ?`,
                [reservation.table_id, reservation.reservation_date, reservation.time_slot, reservationId]
            );
            if (clash.length > 0) {
                req.flash('error', `That table is already booked for this slot (reservation #${clash[0].id}).`);
                return res.redirect('/admin/reservations');
            }
        }

        await db.query('UPDATE reservations SET status = ?, cancellation_reason = ? WHERE id = ?', [status, reason, reservationId]);
        req.flash('success', `Reservation #${reservationId} set to ${status}.`);
        res.redirect('/admin/reservations');
    } catch (err) {
        console.error('Update reservation status error:', err.message);
        req.flash('error', 'Could not update that reservation.');
        res.redirect('/admin/reservations');
    }
});

function validateTable({ table_number, capacity, location }) {
    const number = String(table_number || '').trim();
    const seats = Number(capacity);
    if (!number) return { error: 'Table number is required.' };
    if (number.length > 20) return { error: 'Table number must be 20 characters or fewer.' };
    if (!Number.isInteger(seats) || seats < 1) return { error: 'Capacity must be a whole number of at least 1.' };
    if (seats > 100) return { error: 'Capacity looks too large — check the number.' };
    return { value: { table_number: number, capacity: seats, location: String(location || '').trim() || null } };
}

app.get('/admin/tables/new', requireRole('admin'), (req, res) => {
    res.render('admin/admin_table_form', { table: null, values: { table_number: '', capacity: '', location: '', image: null } });
});

app.post('/admin/tables', requireRole('admin'), upload.single('image'), async (req, res) => {
    const { error, value } = validateTable(req.body);
    if (error) {
        req.flash('error', error);
        return res.redirect('/admin/tables/new');
    }
    const image = req.file ? req.file.filename : null;
    try {
        await db.query(
            'INSERT INTO restaurant_tables (table_number, capacity, location, image) VALUES (?, ?, ?, ?)',
            [value.table_number, value.capacity, value.location, image]
        );
        req.flash('success', `Table ${value.table_number} added.`);
        res.redirect('/admin/tables');
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            req.flash('error', `Table ${value.table_number} already exists.`);
            return res.redirect('/admin/tables/new');
        }
        console.error('Create table error:', err.message);
        req.flash('error', 'Could not add that table.');
        res.redirect('/admin/tables/new');
    }
});

app.get('/admin/tables/:id/edit', requireRole('admin'), async (req, res) => {
    try {
        const [[table]] = await db.query(
            'SELECT id, table_number, capacity, location, image FROM restaurant_tables WHERE id = ?',
            [req.params.id]
        );
        if (!table) {
            req.flash('error', 'Table not found.');
            return res.redirect('/admin/tables');
        }
        res.render('admin/admin_table_form', { table, values: table });
    } catch (err) {
        console.error('Edit table form error:', err.message);
        req.flash('error', 'Could not open that table.');
        res.redirect('/admin/tables');
    }
});

app.post('/admin/tables/:id/update', requireRole('admin'), upload.single('image'), async (req, res) => {
    const tableId = req.params.id;
    const { error, value } = validateTable(req.body);
    if (error) {
        req.flash('error', error);
        return res.redirect(`/admin/tables/${tableId}/edit`);
    }
    let image = req.body.currentImage || null;
    if (req.file) image = req.file.filename;
    try {
        const [[biggest]] = await db.query(
            `SELECT MAX(party_size) AS largest FROM reservations
             WHERE table_id = ? AND status IN ('pending','confirmed')`,
            [tableId]
        );
        if (biggest.largest && value.capacity < biggest.largest) {
            req.flash('error', `Cannot shrink below ${biggest.largest} — an active booking needs that many seats.`);
            return res.redirect(`/admin/tables/${tableId}/edit`);
        }

        const [result] = await db.query(
            'UPDATE restaurant_tables SET table_number = ?, capacity = ?, location = ?, image = ? WHERE id = ?',
            [value.table_number, value.capacity, value.location, image, tableId]
        );
        if (result.affectedRows === 0) {
            req.flash('error', 'Table not found.');
            return res.redirect('/admin/tables');
        }
        req.flash('success', `Table ${value.table_number} updated.`);
        res.redirect('/admin/tables');
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            req.flash('error', `Table ${value.table_number} already exists.`);
            return res.redirect(`/admin/tables/${tableId}/edit`);
        }
        console.error('Update table error:', err.message);
        req.flash('error', 'Could not update that table.');
        res.redirect(`/admin/tables/${tableId}/edit`);
    }
});

app.post('/admin/users/:id/role', requireRole('admin'), async (req, res) => {
    const userId = Number(req.params.id);
    const role = normaliseRole(req.body.role);

    if (userId === req.session.user.id) {
        req.flash('error', 'You cannot change your own role while logged in as it.');
        return res.redirect('/admin/users');
    }

    try {
        const [[target]] = await db.query('SELECT name, role FROM users WHERE id = ?', [userId]);
        if (!target) {
            req.flash('error', 'User not found.');
            return res.redirect('/admin/users');
        }
        if (target.role === role) {
            req.flash('error', `${target.name} is already ${role === 'admin' ? 'an admin' : 'a user'}.`);
            return res.redirect('/admin/users');
        }
        if (target.role === 'admin' && role === 'user') {
            const [[adminCount]] = await db.query(`SELECT COUNT(*) AS n FROM users WHERE role = 'admin'`);
            if (adminCount.n <= 1) {
                req.flash('error', 'Cannot demote the last remaining admin account.');
                return res.redirect('/admin/users');
            }
        }

        await db.query('UPDATE users SET role = ? WHERE id = ?', [role, userId]);
        req.flash('success', `${target.name} is now ${role === 'admin' ? 'an admin' : 'a user'}.`);
        res.redirect('/admin/users');
    } catch (err) {
        console.error('Update user role error:', err.message);
        req.flash('error', 'Could not update that role.');
        res.redirect('/admin/users');
    }
});

app.get('/admin/change-password', requireRole('admin'), (req, res) => {
    res.render('admin/admin_change_password', { error: null });
});

app.post('/admin/change-password', requireRole('admin'), async (req, res) => {
    const userId = req.session.user.id;
    const currentPassword = String(req.body.currentPassword || '');
    const newPassword = String(req.body.newPassword || '');
    const confirmPassword = String(req.body.confirmPassword || '');

    if (newPassword.length < 8) {
        return res.status(400).render('admin/admin_change_password', { error: 'New password must have at least 8 characters.' });
    }
    if (newPassword !== confirmPassword) {
        return res.status(400).render('admin/admin_change_password', { error: 'New passwords do not match.' });
    }

    try {
        const [[match]] = await db.query(
            'SELECT id FROM users WHERE id = ? AND password_hash = SHA1(?)',
            [userId, currentPassword]
        );
        if (!match) {
            return res.status(401).render('admin/admin_change_password', { error: 'Current password is incorrect.' });
        }

        await db.query('UPDATE users SET password_hash = SHA1(?) WHERE id = ?', [newPassword, userId]);
        req.flash('success', 'Password updated.');
        res.redirect('/admin');
    } catch (err) {
        console.error('Change password error:', err.message);
        res.status(500).render('admin/admin_change_password', { error: 'Could not update your password right now.' });
    }
});

// ============ USER ROUTES ============

const TIME_SLOTS = ['17:00','17:30','18:00','18:30','19:00','19:30','20:00','20:30','21:00','21:30'];

app.get('/user/slots', requireRole('user'), async (req, res) => {
    const { table_id, date, exclude } = req.query;
    if (!table_id || !date) return res.json({ available: [] });

    try {
        const params = [table_id, date];
        let sql = `SELECT time_slot FROM reservations
                   WHERE table_id = ? AND reservation_date = ?
                     AND status IN ('pending','confirmed')`;
        if (exclude) { sql += ' AND id != ?'; params.push(exclude); }

        const [booked] = await db.query(sql, params);
        const taken = booked.map(r => String(r.time_slot).slice(0, 5));
        res.json({ available: TIME_SLOTS.filter(slot => !taken.includes(slot)) });
    } catch (err) {
        console.error('Slot availability error:', err.message);
        res.status(500).json({ available: [], error: true });
    }
});

app.get('/user/dashboard', requireRole('user'), async (req, res) => {
    try {
        const userId = req.session.user.id;
        const { orderBy, sort, dir } = buildSort('myReservations', req.query, 'date', 'desc');

        const [myReservations] = await db.query(
            `SELECT r.id, r.reservation_date, r.time_slot, r.party_size, r.remarks, r.status, t.table_number
             FROM reservations r
             JOIN restaurant_tables t ON t.id = r.table_id
             WHERE r.user_id = ?
             ${orderBy}`,
            [userId]
        );

        const [availableTables] = await db.query(
            `SELECT id, table_number, capacity, location
             FROM restaurant_tables ORDER BY table_number`
        );

        res.render('user/user_dashboard', {
            myReservations,
            availableTables,
            title: 'My Dashboard',
            sort, dir,
            sortLink: (col) => sortLink(req.query, col, sort, dir)
        });
    } catch (err) {
        console.error('User dashboard query error:', err.message);
        res.status(500).send('Error loading user dashboard');
    }
});

app.get('/user/reservations/:id/edit', requireRole('user'), async (req, res) => {
    try {
        const userId = req.session.user.id;
        const reservationId = req.params.id;

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

        const [availableTables] = await db.query(
            'SELECT id, table_number, capacity FROM restaurant_tables ORDER BY table_number'
        );

        res.render('user/user_reservations', {
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
app.post('/user/reservations', requireRole('user'), async (req, res) => {
    const { table_id, party_size, reservation_date, time_slot, remarks } = req.body;
    const userId = req.session.user.id;

    if (isPastDate(reservation_date)) {
        return res.status(400).send('Reservation date cannot be in the past');
    }
    if (!TIME_SLOTS.includes(time_slot)) {
        return res.status(400).send('Please choose a valid time slot');
    }

    try {
        const [[table]] = await db.query(
            'SELECT capacity FROM restaurant_tables WHERE id = ?',
            [table_id]
        );
        if (!table) {
            return res.status(400).send('Selected table does not exist');
        }
        if (Number(party_size) > table.capacity) {
            return res.status(400).send(`Party size exceeds this table's capacity (${table.capacity})`);
        }

        const [existing] = await db.query(
            `SELECT id FROM reservations 
             WHERE table_id = ? AND reservation_date = ? AND time_slot = ? 
             AND status IN ('pending', 'confirmed')`,
            [table_id, reservation_date, time_slot]
        );

        if (existing.length > 0) {
            return res.status(400).send('Table is already booked for this time slot');
        }

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
app.post('/user/reservations/:id/update', requireRole('user'), async (req, res) => {
    const { table_id, party_size, reservation_date, time_slot, remarks } = req.body;
    const reservationId = req.params.id;
    const userId = req.session.user.id;

    if (isPastDate(reservation_date)) {
        return res.status(400).send('Reservation date cannot be in the past');
    }
    if (!TIME_SLOTS.includes(time_slot)) {
        return res.status(400).send('Please choose a valid time slot');
    }

    try {
        const [[table]] = await db.query(
            'SELECT capacity FROM restaurant_tables WHERE id = ?',
            [table_id]
        );
        if (!table) {
            return res.status(400).send('Selected table does not exist');
        }
        if (Number(party_size) > table.capacity) {
            return res.status(400).send(`Party size exceeds this table's capacity (${table.capacity})`);
        }

        const [existing] = await db.query(
            `SELECT id FROM reservations
             WHERE table_id = ? AND reservation_date = ? AND time_slot = ?
             AND status IN ('pending', 'confirmed')
             AND id != ?`,
            [table_id, reservation_date, time_slot, reservationId]
        );
        if (existing.length > 0) {
            return res.status(400).send('Table is already booked for this time slot');
        }

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

// ================================================================
// FIXED: Delete/Cancel reservation (removed cancellation_reason)
// ================================================================
app.post('/user/reservations/:id/delete', requireRole('user'), async (req, res) => {
    const reservationId = req.params.id;
    const userId = req.session.user.id;

    try {
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

        // ✅ FIXED: Removed cancellation_reason column
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

// ================================================================
// FIXED: Permanently remove a reservation from the user's own history
// ================================================================
app.post('/user/reservations/:id/remove', requireRole('user'), async (req, res) => {
    const reservationId = req.params.id;
    const userId = req.session.user.id;

    try {
        const [rows] = await db.query(
            'SELECT status FROM reservations WHERE id = ? AND user_id = ?',
            [reservationId, userId]
        );

        if (rows.length === 0) {
            return res.status(404).send('Reservation not found');
        }
        if (!['cancelled', 'rejected'].includes(rows[0].status)) {
            return res.status(400).send('Only cancelled or rejected reservations can be removed.');
        }

        // ✅ ADDED: Delete the reservation
        await db.query('DELETE FROM reservations WHERE id = ? AND user_id = ?', [reservationId, userId]);
        res.redirect('/user/dashboard');
    } catch (err) {
        console.error('Remove reservation error:', err.message);
        res.status(500).send('Error removing reservation');
    }
});

// ================================================================
// SERVER STARTUP
// ================================================================
const PORT = process.env.PORT || 3000;
if (require.main === module) {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = { app, buildFilter, buildSort, sortLink, hashPassword, verifyPassword, requireRole, isPastDate, validateTable, TIME_SLOTS };