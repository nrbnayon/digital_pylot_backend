const express = require('express');
const router = express.Router();
const { loginUser, refreshToken, logoutUser, getUserProfile } = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');

router.post('/login', loginUser);
router.get('/refresh', refreshToken);
router.post('/logout', logoutUser);
router.get('/me', protect, getUserProfile);

module.exports = router;
