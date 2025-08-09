require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();

// Middleware
app.use(cors({
  origin: 'http://localhost:5173', // Your React app's URL
  credentials: true
}));
app.use(bodyParser.json());

// Database connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: {
    rejectUnauthorized: false // Required for Render.com PostgreSQL
  }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

// Helper function to authenticate token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Routes

// User Registration
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email, hashedPassword]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: user.rows[0].id, email: user.rows[0].email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.json({ 
      token, 
      user: { 
        id: user.rows[0].id, 
        name: user.rows[0].name, 
        email: user.rows[0].email 
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Profile Section
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    // Get user details
    const userResult = await pool.query(
      'SELECT id, name, email, created_at FROM users WHERE id = $1',
      [req.user.id]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Get user's created events
    const eventsResult = await pool.query(
      'SELECT id, title, date, location FROM events WHERE user_id = $1',
      [req.user.id]
    );
    
    // Get user's bookings with event details
    const bookingsResult = await pool.query(
      `SELECT b.id, b.seats, b.created_at as booking_date, 
       e.id as event_id, e.title, e.date, e.location 
       FROM bookings b 
       JOIN events e ON b.event_id = e.id 
       WHERE b.user_id = $1`,
      [req.user.id]
    );
    
    res.json({
      user: userResult.rows[0],
      events: eventsResult.rows,
      bookings: bookingsResult.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch profile data' });
  }
});

// Update Profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    let updateQuery = 'UPDATE users SET name = $1, email = $2';
    let queryParams = [name, email];
    
    // If password is provided, hash it and add to update
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateQuery += ', password = $3';
      queryParams.push(hashedPassword);
    }
    
    updateQuery += ' WHERE id = $' + (queryParams.length + 1) + ' RETURNING id, name, email';
    queryParams.push(req.user.id);
    
    const result = await pool.query(updateQuery, queryParams);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Events CRUD Operations

// Create Event
app.post('/api/events', authenticateToken, async (req, res) => {
  try {
    const { title, description, date, location, available_seats } = req.body;
    const result = await pool.query(
      'INSERT INTO events (title, description, date, location, available_seats, user_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [title, description, date, location, available_seats, req.user.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create event' });
  }
});

// Get All Events
app.get('/api/events', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM events');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});

// Get Single Event with Booking Status (for authenticated users)
app.get('/api/events/:id', authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.id;
    
    // Get event details
    const eventResult = await pool.query('SELECT * FROM events WHERE id = $1', [eventId]);
    if (eventResult.rows.length === 0) {
      return res.status(404).json({ error: 'Event not found' });
    }
    
    // Check if user has already booked this event
    const bookingResult = await pool.query(
      'SELECT id, seats FROM bookings WHERE event_id = $1 AND user_id = $2',
      [eventId, req.user.id]
    );
    
    const event = eventResult.rows[0];
    const response = {
      ...event,
      hasBooked: bookingResult.rows.length > 0,
      bookingDetails: bookingResult.rows.length > 0 ? bookingResult.rows[0] : null
    };
    
    res.json(response);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch event' });
  }
});

// Update Event
app.put('/api/events/:id', authenticateToken, async (req, res) => {
  try {
    const { title, description, date, location, available_seats } = req.body;
    const result = await pool.query(
      'UPDATE events SET title = $1, description = $2, date = $3, location = $4, available_seats = $5 WHERE id = $6 AND user_id = $7 RETURNING *',
      [title, description, date, location, available_seats, req.params.id, req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Event not found or not authorized' });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update event' });
  }
});

// Delete Event
app.delete('/api/events/:id', authenticateToken, async (req, res) => {
  try {
    // First delete all bookings for this event
    await pool.query('DELETE FROM bookings WHERE event_id = $1', [req.params.id]);
    
    // Then delete the event
    const result = await pool.query(
      'DELETE FROM events WHERE id = $1 AND user_id = $2 RETURNING *',
      [req.params.id, req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Event not found or not authorized' });
    }
    
    res.json({ message: 'Event and associated bookings deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete event' });
  }
});

// Bookings CRUD Operations

// Create Booking (with check for existing booking)
app.post('/api/bookings', authenticateToken, async (req, res) => {
  try {
    const { event_id, seats } = req.body;
    
    // Check if user has already booked this event
    const existingBooking = await pool.query(
      'SELECT id FROM bookings WHERE event_id = $1 AND user_id = $2',
      [event_id, req.user.id]
    );
    
    if (existingBooking.rows.length > 0) {
      return res.status(400).json({ error: 'You have already booked this event' });
    }
    
    // Check event availability
    const event = await pool.query('SELECT * FROM events WHERE id = $1', [event_id]);
    if (event.rows.length === 0) {
      return res.status(404).json({ error: 'Event not found' });
    }
    
    if (event.rows[0].available_seats < seats) {
      return res.status(400).json({ error: 'Not enough seats available' });
    }
    
    // Create booking
    const bookingResult = await pool.query(
      'INSERT INTO bookings (event_id, user_id, seats) VALUES ($1, $2, $3) RETURNING *',
      [event_id, req.user.id, seats]
    );
    
    // Update available seats
    await pool.query(
      'UPDATE events SET available_seats = available_seats - $1 WHERE id = $2',
      [seats, event_id]
    );
    
    res.status(201).json(bookingResult.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create booking' });
  }
});

// Get User Bookings with more details
app.get('/api/bookings', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT b.id, b.seats, b.created_at as booking_date, 
       e.id as event_id, e.title, e.description, e.date, e.location, 
       u.name as organizer_name, u.email as organizer_email
       FROM bookings b 
       JOIN events e ON b.event_id = e.id
       JOIN users u ON e.user_id = u.id
       WHERE b.user_id = $1`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch bookings' });
  }
});

// Cancel Booking
app.delete('/api/bookings/:id', authenticateToken, async (req, res) => {
  try {
    // Get booking details first
    const booking = await pool.query(
      'SELECT * FROM bookings WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    
    if (booking.rows.length === 0) {
      return res.status(404).json({ error: 'Booking not found or not authorized' });
    }
    
    // Delete booking
    await pool.query(
      'DELETE FROM bookings WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    
    // Return seats to event
    await pool.query(
      'UPDATE events SET available_seats = available_seats + $1 WHERE id = $2',
      [booking.rows[0].seats, booking.rows[0].event_id]
    );
    
    res.json({ message: 'Booking cancelled successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to cancel booking' });
  }
});

// Initialize database tables if they don't exist
async function initializeDatabase() {
  try {
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create events table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS events (
        id SERIAL PRIMARY KEY,
        title VARCHAR(100) NOT NULL,
        description TEXT,
        date TIMESTAMP NOT NULL,
        location VARCHAR(100) NOT NULL,
        available_seats INTEGER NOT NULL,
        user_id INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create bookings table with unique constraint to prevent duplicate bookings
    await pool.query(`
      CREATE TABLE IF NOT EXISTS bookings (
        id SERIAL PRIMARY KEY,
        event_id INTEGER REFERENCES events(id),
        user_id INTEGER REFERENCES users(id),
        seats INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (event_id, user_id) -- This ensures one booking per user per event
      )
    `);
    
    console.log('Database tables initialized');
  } catch (err) {
    console.error('Database initialization failed:', err);
  }
}

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  initializeDatabase();
});