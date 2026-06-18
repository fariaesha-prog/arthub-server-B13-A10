const express = require("express");
const router = express.Router();
const Artwork = require("../models/Artwork"); // Path to your schema model

// POST: Save a new artwork release
router.post("/artworks", async (req, res) => {
  try {
    const { title, description, price, category, imageUrl } = req.body;

    // Simple validation check
    if (!title || !description || !price || !category || !imageUrl) {
      return res.status(400).json({ message: "All form fields are required." });
    }

    const newArtwork = new Artwork({
      title,
      description,
      price: Number(price),
      category,
      imageUrl
    });

    const savedArtwork = await newArtwork.save();
    res.status(201).json(savedArtwork);
  } catch (error) {
    console.error("Database save error:", error);
    res.status(500).json({ message: "Server error: Could not save artwork details." });
  }
});

module.exports = router;