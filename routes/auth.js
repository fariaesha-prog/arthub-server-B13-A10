const express = require('express');
const router = express.Router();
const User = require('../models/User'); // This assumes your model is in ../models/User

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) return res.status(404).json({ message: "User not found." });

        // Simple check (we will add encryption later!)
        if (user.password !== password) {
            return res.status(401).json({ message: "Invalid credentials." });
        }

        res.status(200).json({ 
            message: "Login successful!", 
            user: { name: user.name, role: user.role } 
        });
    } catch (err) {
        res.status(500).json({ message: "Server error during sign in." });
    }
});

module.exports = router;