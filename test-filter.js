const assert = require('assert');
const { buildFilter } = require('./app');

assert.deepStrictEqual(buildFilter({}), { clause: '', params: [] });
assert.deepStrictEqual(buildFilter({ status: 'pending' }),
    { clause: ' WHERE r.status = ?', params: ['pending'] });
assert.deepStrictEqual(buildFilter({ date: '2026-07-20' }),
    { clause: ' WHERE r.reservation_date = ?', params: ['2026-07-20'] });
assert.deepStrictEqual(buildFilter({ status: 'confirmed', date: '2026-07-20' }),
    { clause: ' WHERE r.status = ? AND r.reservation_date = ?', params: ['confirmed', '2026-07-20'] });
// empty strings are absent, not filters
assert.deepStrictEqual(buildFilter({ status: '', date: '' }), { clause: '', params: [] });

console.log('buildFilter ok');
