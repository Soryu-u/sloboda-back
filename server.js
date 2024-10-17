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

//Перевірка токену

const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: "Доступ відхилено" });
  }

  jwt.verify(token, "your-secret-key", (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
};

  


// User schema

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
  token: { type: String },  // Зберігаємо токен
});

const User = mongoose.model("User", userSchema);

module.exports = User;

// Register route


app.post("/auth/register", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "Заповніть всі поля" });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email вже зареєстровано" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });

    await newUser.save();

    // Генерація токена
    const token = jwt.sign({ id: newUser._id }, "your-secret-key", { expiresIn: "1h" });

    // Оновлення користувача з токеном
    newUser.token = token;
    await newUser.save();

    res.status(201).json({
      message: "Користувача зареєстровано",
      success: true,
      user: {
        username: newUser.username,
        email: newUser.email,
      },
      token,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// POST: Login route
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Заповніть всі поля" });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: "Користувача не знайдено" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Неправильний пароль" });
    }

    // Генерація токена
    const token = jwt.sign({ id: user._id }, "your-secret-key", { expiresIn: "1h" });

    // Оновлення користувача з токеном
    user.token = token;
    await user.save();

    res.status(200).json({
      message: "Вхід успішний",
      success: true,
      user: {
        username: user.username,
        email: user.email,
      },
      token,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


//Профіль
app.get("/auth/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "Користувача не знайдено" });
    }
    res.status(200).json({
      username: user.username,
      email: user.email,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


//Зміна паролю

app.post('/auth/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  try {
    const user = await User.findById(req.user.id); // Отримуємо користувача з токену

    if (!user) {
      return res.status(404).json({ message: "Користувача не знайдено" });
    }

    // Перевірка старого пароля
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Неправильний поточний пароль" });
    }

    // Хешуємо новий пароль
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    // Зберігаємо зміни
    await user.save();

    res.json({ message: "Пароль успішно змінено" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
