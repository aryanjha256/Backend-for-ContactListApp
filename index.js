// Import required modules
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectID } = require('mongodb');

// Create an Express app
const app = express();
app.use(express.json());
app.use(cors());

// MongoDB connection details
const MONGODB_URL = 'mongodb+srv://itsaryankumarhere:WyzTQiZukxXO13Nk@firstmongo.z91x1jj.mongodb.net/?retryWrites=true&w=majority';
const DB_NAME = 'contacts-app';

// Secret key for JWT
const SECRET_KEY = '5Ad9mM^9wQ4@';

// Number of salt rounds for bcrypt password hashing
const SALT_ROUNDS = 6;

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.header('Authorization');
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.sendStatus(401);
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(403).json({ message: 'Token expired' });
            }
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
};

// API endpoint for user registration
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            res.status(400).json({ error: 'Please enter a valid username and password.' });
            return;
        }

        // Connect to MongoDB
        const client = await MongoClient.connect(MONGODB_URL);
        const db = client.db(DB_NAME);
        const usersCollection = db.collection('users');

        // Check if the username already exists in MongoDB

        const existingUser = await usersCollection.findOne({ username });
        if (existingUser) {
            res.status(400).json({ error: 'Username already taken.' });
            return;
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        // Store the user details in MongoDB
        await usersCollection.insertOne({ username, password: hashedPassword });

        res.sendStatus(201);
    } catch (error) {
        console.error(error);
        res.sendStatus(500);
    }
});

// API endpoint for user login
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Retrieve the user details from MongoDB
        const client = await MongoClient.connect(MONGODB_URL);
        const db = client.db(DB_NAME);
        const usersCollection = db.collection('users');
        const user = await usersCollection.findOne({ username });

        if (!user) {
            return res.status(404).send('User not found');
        }

        // Compare the hashed password
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).send('Invalid password');
        }

        // Create a JWT token
        const token = jwt.sign({ username: user.username }, SECRET_KEY);

        res.json({ token });
    } catch (error) {
        console.error(error);
        res.sendStatus(500);
    }
});

// API endpoint to get the list of contacts for a logged-in user
app.get('/contacts', authenticateToken, async (req, res) => {
    try {
        const { username } = req.user;

        // Retrieve the contacts for the logged-in user from MongoDB
        const client = await MongoClient.connect(MONGODB_URL);
        const db = client.db(DB_NAME);
        const contactsCollection = db.collection('contacts');
        const contacts = await contactsCollection.find({ username }).toArray();

        res.json(contacts);
    } catch (error) {
        console.error(error);
        res.sendStatus(500);
    }
});

// API endpoint to create a new contact
app.post('/contacts', authenticateToken, async (req, res) => {
    try {
        const { username } = req.user;
        const { name, email, phone } = req.body;

        // Store the new contact in MongoDB
        const client = await MongoClient.connect(MONGODB_URL);
        const db = client.db(DB_NAME);
        const contactsCollection = db.collection('contacts');
        await contactsCollection.insertOne({ username, name, email, phone });

        res.sendStatus(201);
    } catch (error) {
        console.error(error);
        res.sendStatus(500);
    }
});

// API endpoint to update an existing contact
app.put('/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const { username } = req.user;
        const { id } = req.params;
        const { name, email, phone } = req.body;

        // Update the contact in MongoDB
        const client = await MongoClient.connect(MONGODB_URL);
        const db = client.db(DB_NAME);
        const contactsCollection = db.collection('contacts');
        await contactsCollection.updateOne({ _id: ObjectID(id), username }, { $set: { name, email, phone } });

        res.sendStatus(200);
    } catch (error) {
        console.error(error);
        res.sendStatus(500);
    }
});

// API endpoint to delete a contact
app.delete('/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const { username } = req.user;
        const { id } = req.params;

        // Delete the contact from MongoDB
        const client = await MongoClient.connect(MONGODB_URL);
        const db = client.db(DB_NAME);
        const contactsCollection = db.collection('contacts');
        await contactsCollection.deleteOne({ _id: ObjectID(id), username });

        res.sendStatus(200);
    } catch (error) {
        console.error(error);
        res.sendStatus(500);
    }
});

// Start the server
app.listen(process.env.PORT || 3000, () => {
    console.log('Server is running on http://localhost:3000');
});
