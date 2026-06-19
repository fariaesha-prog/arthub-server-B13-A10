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

// Initialize MongoDB Connection
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

// Middleware: Verify Token
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
    const usersCollection = db.collection("user");
    if (await usersCollection.findOne({ email })) return res.status(400).json({ message: "Email exists." });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { name, email, password: hashedPassword, role: role || "user", createdAt: new Date() };
    const result = await usersCollection.insertOne(newUser);

    const token = jwt.sign({ id: result.insertedId, email, role: newUser.role, name }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.status(201).json({ success: true, token, user: { name, email, role: newUser.role } });
  } catch (error) {
    res.status(500).json({ message: "Server error." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.collection("user").findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ message: "Invalid credentials." });

    const token = jwt.sign({ id: user._id, email: user.email, role: user.role, name: user.name }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user: { name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    res.status(500).json({ message: "Server error." });
  }
});

app.get("/api/auth/me", authenticateToken, async (req, res) => {
  const user = await db.collection("user").findOne({ _id: new ObjectId(req.user.id) });
  user ? res.json({ user: { name: user.name, email: user.email, role: user.role } }) : res.status(404).json({ message: "Not found." });
});

// ==========================================
// 🎨 ARTWORK ENDPOINTS
// ==========================================

app.post("/api/artworks", authenticateToken, async (req, res) => {
  try {
    const { title, description, price, category, imageUrl } = req.body;
    const newArtwork = { title, description, price: Number(price), category, imageUrl, artist: { id: req.user.id, email: req.user.email, name: req.user.name }, createdAt: new Date() };
    const result = await db.collection("artworks").insertOne(newArtwork);
    res.status(201).json({ success: true, insertedId: result.insertedId });
  } catch (error) {
    res.status(500).json({ message: "Database error." });
  }
});

app.get("/api/artworks", authenticateToken, async (req, res) => {
  const artworks = await db.collection("artworks").find({ "artist.email": req.user.email }).sort({ createdAt: -1 }).toArray();
  res.json(artworks);
});

// Fetch one by ID (For Edit Page)
app.get("/api/artworks/:id", authenticateToken, async (req, res) => {
  try {
    const artwork = await db.collection("artworks").findOne({ _id: new ObjectId(req.params.id), "artist.email": req.user.email });
    artwork ? res.json(artwork) : res.status(404).json({ message: "Not found" });
  } catch (error) {
    res.status(500).json({ message: "Error fetching." });
  }
});

// Update artwork
// Update artwork
app.put("/api/artworks/:id", authenticateToken, async (req, res) => {
  try {
    const result = await db.collection("artworks").findOneAndUpdate(
      { _id: new ObjectId(req.params.id), "artist.email": req.user.email },
      { $set: { ...req.body, price: Number(req.body.price), updatedAt: new Date() } },
      { returnDocument: "after" }
    );
    result ? res.json(result) : res.status(404).json({ message: "Not found or unauthorized." });
  } catch (error) {
    res.status(500).json({ message: "Update failed." });
  }
});

app.delete("/api/artworks/:id", authenticateToken, async (req, res) => {
  try {
    const result = await db.collection("artworks").deleteOne({ _id: new ObjectId(req.params.id), "artist.email": req.user.email });
    result.deletedCount === 1 ? res.json({ message: "Deleted successfully" }) : res.status(404).json({ message: "Not found." });
  } catch (error) {
    res.status(500).json({ message: "Delete failed." });
  }
});

app.listen(PORT, () => console.log(`📡 Server running on http://localhost:${PORT}`));