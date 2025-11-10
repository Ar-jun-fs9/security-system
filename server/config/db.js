const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// Test the connection
pool.connect()
    .then(client => {
        console.log('Successfully connected to database');
        client.release();
    })
    .catch(err => {
        console.error('Error connecting to the database:', err.stack);
    });

// Helper function to execute queries with transaction
const executeQuery = async (text, params) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const result = await client.query(text, params);
        await client.query('COMMIT');
        return result;
    } catch (e) {
        await client.query('ROLLBACK');
        throw e;
    } finally {
        client.release();
    }
};

module.exports = {
    query: executeQuery,
    pool: pool
}; 