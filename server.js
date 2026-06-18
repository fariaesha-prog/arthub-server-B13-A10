import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { MongoClient, ObjectId } from "mongodb";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Global Middleware Config
app.use(cors({
  origin: process.env.CLIENT_URL || "http://localhost:3000",
  credentials: true // Crucial for reading authorization headers safely
}));
app.use(express.json());

// Initialize MongoDB Connection Database Instance
const client = new MongoClient(process.env.MONGODB_URI);
let db;

async function connectDB() {
  try {
    await client.connect();
    // 🔥 Explicitly targeting 'arthub-db' to fetch Better-Auth's folder 
    db = client.db("arthub-db"); 
    console.log("🚀 Connected smoothly to MongoDB Server Database Layer (arthub-db)!");
  } catch (err) {
    console.error("Database connection fault:", err);
  }
}
connectDB();

// Middleware: Verify Token and Extract User Session Data
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Grabs the token from 'Bearer <TOKEN>'

  if (!token) return res.status(401).json({ message: "Access token missing." });

  jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
    if (err) return res.status(403).json({ message: "Invalid or expired token." });
    req.user = decodedUser;
    next();
  });
};

// ==========================================
// 🔐 AUTHENTICATION ENDPOINTS
// ==========================================

// 1. User Registration Route Handler
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All basic credentials fields are required." });
    }

    // Switched from "users" to singular "user" to match Better-Auth
    const usersCollection = db.collection("user");

    // Check if the user email already exists
    const userExists = await usersCollection.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "An account with this email already exists." });
    }

    // Hash the password securely
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Build the user payload profile
    const newUser = {
      name,
      email,
      password: hashedPassword,
      role: role || "user", // Defaults to 'user' if blank
      createdAt: new Date()
    };

    const result = await usersCollection.insertOne(newUser);

    // Generate the 7-day token immediately on registration for auto-login
    const token = jwt.sign(
      { id: result.insertedId, email: newUser.email, role: newUser.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Return the token so the frontend can catch it and perform an instant login
    res.status(201).json({
      success: true,
      message: "User registered successfully!",
      token,
      user: {
        name: newUser.name,
        email: newUser.email,
        role: newUser.role
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error during registration workflow." });
  }
});

// 2. User Credentials Sign-In & JWT generation Route
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Switched from "users" to singular "user"
    const user = await db.collection("user").findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password combination." });
    }

    // Compare typed credentials with hashed security string
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid email or password combination." });
    }

    // Sign a custom JWT token structured to expire exactly in 7 days
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Send back the session token signature and base non-sensitive parameters
    res.json({
      token,
      user: {
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error during sign in processing." });
  }
});

// 3. Me / Verify Session Route Handler
app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    // Switched from "users" to singular "user"
    const user = await db.collection("user").findOne({ _id: new ObjectId(req.user.id) });
    if (!user) return res.status(404).json({ message: "User profile no longer exists." });

    res.json({
      user: {
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: "Internal verification pipeline error." });
  }
});

// ==========================================
// 🎨 ARTWORK ENDPOINTS
// ==========================================

// POST: Save a new artwork release to the database
app.post("/api/artworks", async (req, res) => {
  try {
    const { title, description, price, category, imageUrl } = req.body;

    // 1. Validation check to ensure no field is blank
    if (!title || !description || !price || !category || !imageUrl) {
      return res.status(400).json({ 
        success: false, 
        message: "Missing required fields. Please fill out the form entirely." 
      });
    }

    // 2. Build out the new document object structure
    const newArtwork = {
      title,
      description,
      price: Number(price),
      category,
      imageUrl,
      // Default artist session data until auth context state passes real identities down
      artist: {
        name: "Aria Nakamura",
        email: "aria@arthub.com"
      },
      createdAt: new Date()
    };

    // 3. Save directly to your native MongoDB database collection ('artworks')
    const artworksCollection = db.collection("artworks");
    const result = await artworksCollection.insertOne(newArtwork);

    // 4. Return success back to your Next.js application layer
    res.status(201).json({ 
      success: true, 
      message: "Artwork added successfully!",
      insertedId: result.insertedId
    });

  } catch (error) {
    console.error("MongoDB Insert Error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Database insertion pipeline fault while saving metadata." 
    });
  }
});

// ==========================================
// 🌐 SYSTEM HEALTH CHECKS
// ==========================================

// Base root route to verify the server is running
app.get("/", (req, res) => {
  res.json({ 
    status: "healthy", 
    message: "ArtHub Backend Server is running smoothly!" 
  });
});

// Start listening for network hits
app.listen(PORT, () => {
  console.log(`📡 Server API engine running on endpoint: http://localhost:${PORT}`);
});