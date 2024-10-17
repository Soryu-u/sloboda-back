const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const uri = "mongodb+srv://szpaku:Bmh2KVs6vxQLJKiv@sloboda.ll4nh.mongodb.net/DnD?retryWrites=true&w=majority&appName=Sloboda";
const cors = require('cors'); // Підключаємо CORS

const app = express();

// Додаємо CORS з налаштуванням для вашого фронтенду
app.use(cors({
  origin: 'http://localhost:3000', // Вказуємо домен фронтенду
  methods: ['GET', 'POST'],
  credentials: true
}));

app.use(express.json());

// MongoDB connection
mongoose.connect(uri)
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch(err => {
    console.error("MongoDB connection error", err);
  });


// User schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
  });
  
  const User = mongoose.model('User', userSchema); // Назва моделі автоматично створить колекцію "users" у MongoDB
  
  module.exports = User;

// Register route

app.post('/auth/register', async (req, res) => {
    const { username, email, password } = req.body;
  
    try {
      // Перевірка, чи існує користувач
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ message: "User already exists" });
      }
  
      // Хешування паролю
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Створення нового користувача
      const newUser = new User({
        username,
        email,
        password: hashedPassword
      });
  
      await newUser.save();
  
      // Генерація JWT токену
      const token = jwt.sign({ id: newUser._id }, 'your-secret-key', { expiresIn: '1h' });
  
      // Відправка відповіді з токеном і даними користувача
      return res.json({
        data: {
          user: {
            id: newUser._id,
            username: newUser.username,
            email: newUser.email,
          },
        },
        token
      });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ message: "Server error" });
    }
  });

// POST: Login route
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    // Find the user in the database
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid password" });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, 'your-secret-key', { expiresIn: '1h' });

    return res.json({
      data: {
        user: {
          id: user._id,
          username: user.username,
        },
      },
      token
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
