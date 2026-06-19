import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { MongoClient, ObjectId } from "mongodb";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({
  origin: process.env.CLIENT_URL || "http://localhost:3000",
  credentials: true
}));
app.use(express.json());

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
// 👤 PROFILE ENDPOINTS
// ==========================================

// Update name/email
app.put("/api/auth/profile", authenticateToken, async (req, res) => {
  try {
    const { name, email } = req.body;
    const usersCollection = db.collection("user");

    // Check if new email is taken by someone else
    if (email !== req.user.email) {
      const existing = await usersCollection.findOne({ email });
      if (existing) return res.status(400).json({ message: "Email already in use." });
    }

    await usersCollection.updateOne(
      { _id: new ObjectId(req.user.id) },
      { $set: { name, email, updatedAt: new Date() } }
    );

    // Issue a new token with updated name/email
    const newToken = jwt.sign(
      { id: req.user.id, email, role: req.user.role, name },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ success: true, token: newToken, user: { name, email, role: req.user.role } });
  } catch (error) {
    res.status(500).json({ message: "Failed to update profile." });
  }
});

// Change password
app.put("/api/auth/change-password", authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await db.collection("user").findOne({ _id: new ObjectId(req.user.id) });
    if (!user) return res.status(404).json({ message: "User not found." });

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) return res.status(400).json({ message: "Current password is incorrect." });

    const hashed = await bcrypt.hash(newPassword, 10);
    await db.collection("user").updateOne(
      { _id: new ObjectId(req.user.id) },
      { $set: { password: hashed, updatedAt: new Date() } }
    );

    res.json({ success: true, message: "Password updated successfully." });
  } catch (error) {
    res.status(500).json({ message: "Failed to change password." });
  }
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

app.get("/api/artworks/public", async (req, res) => {
  try {
    const artworks = await db.collection("artworks").find().sort({ createdAt: -1 }).toArray();
    res.json(artworks);
  } catch (error) {
    res.status(500).json({ message: "Error fetching artworks." });
  }
});

app.get("/api/artworks", authenticateToken, async (req, res) => {
  const artworks = await db.collection("artworks").find({ "artist.email": req.user.email }).sort({ createdAt: -1 }).toArray();
  res.json(artworks);
});

app.get("/api/artworks/:id", authenticateToken, async (req, res) => {
  try {
    const artwork = await db.collection("artworks").findOne({ _id: new ObjectId(req.params.id), "artist.email": req.user.email });
    artwork ? res.json(artwork) : res.status(404).json({ message: "Not found" });
  } catch (error) {
    res.status(500).json({ message: "Error fetching." });
  }
});

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

// ==========================================
// 💰 SALES ENDPOINTS
// ==========================================

app.post("/api/sales", authenticateToken, async (req, res) => {
  try {
    const { artworkId } = req.body;
    const artwork = await db.collection("artworks").findOne({ _id: new ObjectId(artworkId) });
    if (!artwork) return res.status(404).json({ message: "Artwork not found." });
    if (artwork.artist.email === req.user.email) return res.status(400).json({ message: "You cannot buy your own artwork." });

    const existing = await db.collection("sales").findOne({
      artworkId: new ObjectId(artworkId),
      "buyer.email": req.user.email
    });
    if (existing) return res.status(400).json({ message: "You already purchased this artwork." });

    const sale = {
      artworkId: new ObjectId(artworkId),
      artworkTitle: artwork.title,
      artworkImage: artwork.imageUrl,
      price: artwork.price,
      artist: { id: artwork.artist.id, name: artwork.artist.name, email: artwork.artist.email },
      buyer: { id: req.user.id, name: req.user.name, email: req.user.email },
      purchasedAt: new Date()
    };

    await db.collection("sales").insertOne(sale);
    res.status(201).json({ success: true, message: "Artwork purchased successfully!" });
  } catch (error) {
    res.status(500).json({ message: "Purchase failed." });
  }
});

app.get("/api/sales/artist", authenticateToken, async (req, res) => {
  try {
    const sales = await db.collection("sales")
      .find({ "artist.email": req.user.email })
      .sort({ purchasedAt: -1 })
      .toArray();
    res.json(sales);
  } catch (error) {
    res.status(500).json({ message: "Error fetching sales." });
  }
});

app.get("/api/sales/user", authenticateToken, async (req, res) => {
  try {
    const purchases = await db.collection("sales")
      .find({ "buyer.email": req.user.email })
      .sort({ purchasedAt: -1 })
      .toArray();
    res.json(purchases);
  } catch (error) {
    res.status(500).json({ message: "Error fetching purchases." });
  }
});

app.listen(PORT, () => console.log(`📡 Server running on http://localhost:${PORT}`));