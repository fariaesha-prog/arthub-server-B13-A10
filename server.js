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
  credentials: true 
}));
app.use(express.json());

// Initialize MongoDB Connection Database Instance
const client = new MongoClient(process.env.MONGODB_URI);
let db;

async function connectDB() {
  try {
    await client.connect();
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
  const token = authHeader && authHeader.split(" ")[1]; 

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

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All basic credentials fields are required." });
    }

    const usersCollection = db.collection("user");
    const userExists = await usersCollection.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "An account with this email already exists." });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = {
      name,
      email,
      password: hashedPassword,
      role: role || "user", 
      createdAt: new Date()
    };

    const result = await usersCollection.insertOne(newUser);

    const token = jwt.sign(
      { id: result.insertedId, email: newUser.email, role: newUser.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

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

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.collection("user").findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password combination." });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid email or password combination." });
    }

    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

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

app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
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
// 🎨 ARTWORK ENDPOINTS (Your working original + fetch fix)
// ==========================================

// 1. POST: This is your original working upload route
app.post("/api/artworks", async (req, res) => {
  try {
    const { title, description, price, category, imageUrl } = req.body;

    if (!title || !description || !price || !category || !imageUrl) {
      return res.status(400).json({ 
        success: false, 
        message: "Missing required fields. Please fill out the form entirely." 
      });
    }

    const newArtwork = {
      title,
      description,
      price: Number(price),
      category,
      imageUrl,
      artist: {
        name: "Aria Nakamura",
        email: "aria@arthub.com"
      },
      createdAt: new Date()
    };

    const artworksCollection = db.collection("artworks");
    const result = await artworksCollection.insertOne(newArtwork);

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

// 2. GET: Added this so your my-artworks page can actually load the data out of MongoDB!
app.get("/api/artworks", async (req, res) => {
  try {
    const artworksCollection = db.collection("artworks");
    const artworks = await artworksCollection.find({}).sort({ createdAt: -1 }).toArray();
    res.status(200).json(artworks);
  } catch (error) {
    console.error("MongoDB Fetch Error:", error);
    res.status(500).json({ message: "Could not retrieve artworks." });
  }
});

// 3. DELETE: Added to support the delete button on your page
app.delete("/api/artworks/:id", async (req, res) => {
  try {
    const artworksCollection = db.collection("artworks");
    const result = await artworksCollection.deleteOne({ _id: new ObjectId(req.params.id) });
    if (result.deletedCount === 1) {
      res.status(200).json({ message: "Deleted successfully" });
    } else {
      res.status(404).json({ message: "Artwork not found" });
    }
  } catch (error) {
    console.error("MongoDB Delete Error:", error);
    res.status(500).json({ message: "Error deleting artwork" });
  }
});

// ==========================================
// 🌐 SYSTEM HEALTH CHECKS
// ==========================================

app.get("/", (req, res) => {
  res.json({ 
    status: "healthy", 
    message: "ArtHub Backend Server is running smoothly!" 
  });
});

app.listen(PORT, () => {
  console.log(`📡 Server API engine running on endpoint: http://localhost:${PORT}`);
});