const express = require('express');
const mysql = require('mysql2/promise');
const session = require('express-session');
const app = express();

const db = mysql.createPool({
    host: process.env.DB_HOST || 'c237-marlina-mysql.mysql.database.azure.com',
    user: process.env.DB_USER || 'c237_002',
    password: process.env.DB_PASS || 'c237002@2026!',
    database: process.env.DB_NAME || 'c237_002_team2_restaurant_reservation_system',
    ssl: { rejectUnauthorized: true },
    dateStrings: true
});

app.set('view engine', 'ejs');
app.use(express.static('public'));

// ===== ADD THESE TWO LINES =====
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ===== ADD SESSION MIDDLEWARE =====
app.use(session({
    secret: 'your-super-secret-key-change-this',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// DEV ONLY — remove on integration. Fakes a logged-in admin so pages render.
app.use((req, res, next) => {
    req.session = req.session || {};
    req.session.user = { id: 1, name: 'Site Admin', role: 'admin' };
    res.locals.currentUser = req.session.user;
    res.locals.badge = {
        pending: 'warning',
        confirmed: 'success',
        rejected: 'danger',
        cancelled: 'secondary'
    };
    next();
});

function buildFilter({ status, date }) {
    const where = [], params = [];
    if (status) { where.push('r.status = ?'); params.push(status); }
    if (date) { where.push('r.reservation_date = ?'); params.push(date); }
    return { clause: where.length ? ' WHERE ' + where.join(' AND ') : '', params };
}

app.get('/', (req, res) => res.redirect('/admin'));

// ============ ADMIN ROUTES ============
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
        res.render('admin/admin_reservations', { rows, filter: req.query });
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
        res.render('admin/admin_tables', { rows });
    } catch (err) {
        console.error('Tables query error:', err.message);
        res.status(500).send('Error loading tables');
    }
});

app.get('/admin/users', async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT id, name, email, role, created_at FROM users ORDER BY id'
        );
        res.render('admin/admin_users', { rows });
    } catch (err) {
        console.error('Users query error:', err.message);
        res.status(500).send('Error loading users');
    }
});

// chu fon
app.get('/user/dashboard', async (req, res) => {
    try {
        const userId = req.session.user.id;

        const [myReservations] = await db.query(
            `SELECT r.id, r.reservation_date, r.time_slot, r.party_size, r.remarks, r.status, t.table_number
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

        res.render('user/user_dashboard', { 
            myReservations, 
            availableTables,
            title: 'My Dashboard'
        });
    } catch (err) {
        console.error('User dashboard query error:', err.message);
        res.status(500).send('Error loading user dashboard');
    }
});


app.get('/user/reservations/:id/edit', async (req, res) => {
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
app.post('/user/reservations', async (req, res) => {
    const { table_id, party_size, reservation_date, time_slot, remarks } = req.body;
    const userId = req.session.user.id;

    try {
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

// Delete/Cancel reservation
app.post('/user/reservations/:id/delete', async (req, res) => {
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

const PORT = process.env.PORT || 3000;
if (require.main === module) {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = { app, buildFilter };
