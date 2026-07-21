const express = require('express');
const mysql = require('mysql2/promise');
const app = express();

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

app.set('view engine', 'ejs');
app.use(express.static('public'));


 
// Austin - 25005454 - Login and registration
// ==================================================

const { createAuth } = require('./auth');
const { router: authRouter, sessionMiddleware } = createAuth(db);

app.use(express.urlencoded({ extended: false }));
app.use(sessionMiddleware);
app.use(authRouter);

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

// ponytail: two optional filters, so a two-branch builder. Generalize if a third arrives.
function buildFilter({ status, date }) {
    const where = [], params = [];
    if (status) { where.push('r.status = ?'); params.push(status); }
    if (date) { where.push('r.reservation_date = ?'); params.push(date); }
    return { clause: where.length ? ' WHERE ' + where.join(' AND ') : '', params };
}

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

const PORT = process.env.PORT || 3000;
if (require.main === module) {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = { app, buildFilter };
