import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { MongoClient, ObjectId } from "mongodb";
import Stripe from "stripe";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

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

const requireAdmin = (req, res, next) => {
  if (req.user.role !== "admin") return res.status(403).json({ message: "Admin access required." });
  next();
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
    const newUser = { name, email, password: hashedPassword, role: role || "user", avatar: null, createdAt: new Date() };
    const result = await usersCollection.insertOne(newUser);
    const token = jwt.sign({ id: result.insertedId, email, role: newUser.role, name }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.status(201).json({ success: true, token, user: { name, email, role: newUser.role, avatar: newUser.avatar } });
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
    res.json({ token, user: { name: user.name, email: user.email, role: user.role, avatar: user.avatar } });
  } catch (error) {
    res.status(500).json({ message: "Server error." });
  }
});

app.get("/api/auth/me", authenticateToken, async (req, res) => {
  const user = await db.collection("user").findOne({ _id: new ObjectId(req.user.id) });
  user ? res.json({ user: { name: user.name, email: user.email, role: user.role, avatar: user.avatar } }) : res.status(404).json({ message: "Not found." });
});

// ==========================================
// 👤 PROFILE ENDPOINTS
// ==========================================

app.put("/api/auth/profile", authenticateToken, async (req, res) => {
  try {
    const { name, email, avatar } = req.body;
    const usersCollection = db.collection("user");
    if (email !== req.user.email) {
      const existing = await usersCollection.findOne({ email });
      if (existing) return res.status(400).json({ message: "Email already in use." });
    }
    await usersCollection.updateOne(
      { _id: new ObjectId(req.user.id) },
      { $set: { name, email, avatar, updatedAt: new Date() } }
    );
    const newToken = jwt.sign(
      { id: req.user.id, email, role: req.user.role, name },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );
    res.json({ success: true, token: newToken, user: { name, email, role: req.user.role, avatar: req.user.avatar } });
  } catch (error) {
    res.status(500).json({ message: "Failed to update profile." });
  }
});

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

app.get("/api/artworks/:id", async (req, res) => {
  try {
    const artwork = await db.collection("artworks").findOne({ _id: new ObjectId(req.params.id) });
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
    const query = req.user.role === "admin"
      ? { _id: new ObjectId(req.params.id) }
      : { _id: new ObjectId(req.params.id), "artist.email": req.user.email };
    const result = await db.collection("artworks").deleteOne(query);
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

// ==========================================
// 👑 ADMIN ENDPOINTS
// ==========================================

app.get("/api/admin/analytics", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [users, artworks, sales] = await Promise.all([
      db.collection("user").find().toArray(),
      db.collection("artworks").find().toArray(),
      db.collection("sales").find().toArray()
    ]);
    const totalUsers = users.filter(u => u.role === "user").length;
    const totalArtists = users.filter(u => u.role === "artist").length;
    const totalRevenue = sales.reduce((sum, s) => sum + s.price, 0);
    const now = new Date();
    const months = Array.from({ length: 6 }, (_, i) => {
      const d = new Date(now.getFullYear(), now.getMonth() - 5 + i, 1);
      return { month: d.toLocaleString("default", { month: "short" }), year: d.getFullYear(), monthIndex: d.getMonth(), amount: 0, count: 0 };
    });
    sales.forEach(sale => {
      const d = new Date(sale.purchasedAt);
      const match = months.find(m => m.monthIndex === d.getMonth() && m.year === d.getFullYear());
      if (match) { match.amount += sale.price; match.count += 1; }
    });
    const categoryMap = {};
    artworks.forEach(a => {
      categoryMap[a.category] = (categoryMap[a.category] || 0) + 1;
    });
    const artworksByCategory = Object.entries(categoryMap).map(([name, count]) => ({ name, count }));
    res.json({ totalUsers, totalArtists, totalArtworks: artworks.length, totalSales: sales.length, totalRevenue, salesByMonth: months, artworksByCategory });
  } catch (error) {
    res.status(500).json({ message: "Error fetching analytics." });
  }
});

app.get("/api/admin/users", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await db.collection("user").find({}, { projection: { password: 0 } }).sort({ createdAt: -1 }).toArray();
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: "Error fetching users." });
  }
});

app.put("/api/admin/users/:id/role", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { role } = req.body;
    if (!["user", "artist", "admin"].includes(role)) return res.status(400).json({ message: "Invalid role." });
    await db.collection("user").updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { role, updatedAt: new Date() } }
    );
    res.json({ success: true, message: "Role updated." });
  } catch (error) {
    res.status(500).json({ message: "Failed to update role." });
  }
});

app.get("/api/admin/artworks", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const artworks = await db.collection("artworks").find().sort({ createdAt: -1 }).toArray();
    res.json(artworks);
  } catch (error) {
    res.status(500).json({ message: "Error fetching artworks." });
  }
});

app.get("/api/admin/transactions", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const sales = await db.collection("sales").find().sort({ purchasedAt: -1 }).toArray();
    res.json(sales);
  } catch (error) {
    res.status(500).json({ message: "Error fetching transactions." });
  }
});

// ==========================================
// 🎭 ARTISTS ENDPOINTS
// ==========================================

app.get("/api/artists/top", async (req, res) => {
  try {
    const sales = await db.collection("sales").find().toArray();
    const artistMap = {};
    sales.forEach(sale => {
      const email = sale.artist?.email;
      if (!email) return;
      if (!artistMap[email]) {
        artistMap[email] = { name: sale.artist.name, email: sale.artist.email, totalSales: 0, totalRevenue: 0 };
      }
      artistMap[email].totalSales += 1;
      artistMap[email].totalRevenue += sale.price;
    });
    const top3 = Object.values(artistMap).sort((a, b) => b.totalSales - a.totalSales).slice(0, 3);
    res.json(top3);
  } catch (error) {
    res.status(500).json({ message: "Error fetching top artists." });
  }
});

app.get("/api/artists", async (req, res) => {
  try {
    const [artists, sales] = await Promise.all([
      db.collection("user").find({ role: "artist" }, { projection: { password: 0 } }).toArray(),
      db.collection("sales").find().toArray()
    ]);
    const salesMap = {};
    sales.forEach(sale => {
      const email = sale.artist?.email;
      if (!email) return;
      if (!salesMap[email]) salesMap[email] = { totalSales: 0, totalRevenue: 0 };
      salesMap[email].totalSales += 1;
      salesMap[email].totalRevenue += sale.price;
    });
    const result = artists.map(a => ({
      name: a.name,
      email: a.email,
      totalSales: salesMap[a.email]?.totalSales || 0,
      totalRevenue: salesMap[a.email]?.totalRevenue || 0
    })).sort((a, b) => b.totalSales - a.totalSales);
    res.json(result);
  } catch (error) {
    res.status(500).json({ message: "Error fetching artists." });
  }
});

// ==========================================
// 💬 COMMENT ENDPOINTS
// ==========================================

app.get("/api/artworks/:id/comments", async (req, res) => {
  try {
    const comments = await db.collection("comments")
      .find({ artworkId: new ObjectId(req.params.id) })
      .sort({ createdAt: -1 })
      .toArray();
    res.json(comments);
  } catch (error) {
    res.status(500).json({ message: "Error fetching comments." });
  }
});

app.post("/api/artworks/:id/comments", authenticateToken, async (req, res) => {
  try {
    const { comment } = req.body;
    if (!comment?.trim()) return res.status(400).json({ message: "Comment cannot be empty." });
    const artworkId = new ObjectId(req.params.id);
    const purchase = await db.collection("sales").findOne({
      artworkId,
      "buyer.email": req.user.email
    });
    if (!purchase) return res.status(403).json({ message: "You must purchase this artwork to comment." });
    const newComment = {
      artworkId,
      userId: new ObjectId(req.user.id),
      userName: req.user.name,
      userEmail: req.user.email,
      comment: comment.trim(),
      createdAt: new Date()
    };
    const result = await db.collection("comments").insertOne(newComment);
    res.status(201).json({ ...newComment, _id: result.insertedId });
  } catch (error) {
    res.status(500).json({ message: "Failed to post comment." });
  }
});

app.put("/api/comments/:id", authenticateToken, async (req, res) => {
  try {
    const { comment } = req.body;
    if (!comment?.trim()) return res.status(400).json({ message: "Comment cannot be empty." });
    const result = await db.collection("comments").findOneAndUpdate(
      { _id: new ObjectId(req.params.id), userEmail: req.user.email },
      { $set: { comment: comment.trim(), updatedAt: new Date() } },
      { returnDocument: "after" }
    );
    result ? res.json(result) : res.status(404).json({ message: "Comment not found or unauthorized." });
  } catch (error) {
    res.status(500).json({ message: "Failed to update comment." });
  }
});

app.delete("/api/comments/:id", authenticateToken, async (req, res) => {
  try {
    const result = await db.collection("comments").deleteOne({
      _id: new ObjectId(req.params.id),
      userEmail: req.user.email
    });
    result.deletedCount === 1
      ? res.json({ message: "Comment deleted." })
      : res.status(404).json({ message: "Comment not found or unauthorized." });
  } catch (error) {
    res.status(500).json({ message: "Failed to delete comment." });
  }
});

// ==========================================
// 💳 STRIPE PAYMENT ENDPOINTS
// ==========================================

app.post("/api/payments/artwork", authenticateToken, async (req, res) => {
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
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [{
        price_data: {
          currency: "usd",
          product_data: {
            name: artwork.title,
            description: artwork.description || "Original artwork from ArtHub",
            images: [artwork.imageUrl],
          },
          unit_amount: Math.round(artwork.price * 100),
        },
        quantity: 1,
      }],
      mode: "payment",
      success_url: `${process.env.CLIENT_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}&type=artwork&artworkId=${artworkId}`,
      cancel_url: `${process.env.CLIENT_URL}/artworks/${artworkId}?cancelled=true`,
      metadata: {
        artworkId: artworkId.toString(),
        buyerEmail: req.user.email,
        buyerName: req.user.name,
        buyerId: req.user.id.toString(),
      }
    });
    res.json({ url: session.url });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to create checkout session." });
  }
});

app.post("/api/payments/subscription", authenticateToken, async (req, res) => {
  try {
    const { tier } = req.body;
    const plans = {
      pro: { name: "ArtHub Pro", price: 999, description: "Up to 9 artwork purchases per month" },
      premium: { name: "ArtHub Premium", price: 1999, description: "Unlimited artwork purchases" }
    };
    const plan = plans[tier];
    if (!plan) return res.status(400).json({ message: "Invalid plan." });
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [{
        price_data: {
          currency: "usd",
          product_data: {
            name: plan.name,
            description: plan.description,
          },
          unit_amount: plan.price,
        },
        quantity: 1,
      }],
      mode: "payment",
      success_url: `${process.env.CLIENT_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}&type=subscription&tier=${tier}`,
      cancel_url: `${process.env.CLIENT_URL}/dashboard/user/subscription?cancelled=true`,
      metadata: {
        userId: req.user.id.toString(),
        userEmail: req.user.email,
        tier,
      }
    });
    res.json({ url: session.url });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to create subscription session." });
  }
});

app.post("/api/payments/verify", authenticateToken, async (req, res) => {
  try {
    const { sessionId, type } = req.body;
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.payment_status !== "paid") {
      return res.status(400).json({ message: "Payment not completed." });
    }
    if (type === "artwork") {
      const artworkId = session.metadata.artworkId;
      const artwork = await db.collection("artworks").findOne({ _id: new ObjectId(artworkId) });
      const existing = await db.collection("sales").findOne({
        artworkId: new ObjectId(artworkId),
        "buyer.email": session.metadata.buyerEmail
      });
      if (!existing && artwork) {
        const sale = {
          artworkId: new ObjectId(artworkId),
          artworkTitle: artwork.title,
          artworkImage: artwork.imageUrl,
          price: artwork.price,
          artist: { id: artwork.artist.id, name: artwork.artist.name, email: artwork.artist.email },
          buyer: { id: session.metadata.buyerId, name: session.metadata.buyerName, email: session.metadata.buyerEmail },
          stripeSessionId: sessionId,
          purchasedAt: new Date()
        };
        await db.collection("sales").insertOne(sale);
      }
      res.json({ success: true, type: "artwork" });
    } else if (type === "subscription") {
      const { tier, userId } = session.metadata;
      await db.collection("user").updateOne(
        { _id: new ObjectId(userId) },
        { $set: { subscriptionTier: tier, updatedAt: new Date() } }
      );
      res.json({ success: true, type: "subscription", tier });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to verify payment." });
  }
});

app.listen(PORT, () => console.log(`📡 Server running on http://localhost:${PORT}`));