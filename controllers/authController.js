const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const generateAccessToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET || 'secret', {
    expiresIn: '15m',
  });
};

const generateRefreshToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_REFRESH_SECRET || 'refresh_secret', {
    expiresIn: '7d', // 7 days
  });
};

// @desc    Auth user & get token
// @route   POST /api/auth/login
// @access  Public
const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      
      if (user.status !== 'Active') {
        return res.status(403).json({ message: 'Account is suspended or banned' });
      }

      const accessToken = generateAccessToken(user._id);
      const refreshToken = generateRefreshToken(user._id);

      // Save refresh token to user
      user.refreshToken = refreshToken;
      await user.save();

      // Log action
      await AuditLog.create({
        user: user._id,
        action: 'LOGIN',
        target: user._id,
        details: { ip: req.ip }
      });

      // Send refresh token in httpOnly cookie
      res.cookie('jwt', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      res.json({
        _id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        permissions: user.permissions,
        token: accessToken, // 15min max memory
      });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Refresh access token
// @route   GET /api/auth/refresh
// @access  Public
const refreshToken = async (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.status(401).json({ message: 'Unauthorized' });

  const refreshToken = cookies.jwt;

  try {
    const user = await User.findOne({ refreshToken });
    if (!user) return res.status(403).json({ message: 'Forbidden' });

    jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET || 'refresh_secret',
      (err, decoded) => {
        if (err || user._id.toString() !== decoded.id) {
          return res.status(403).json({ message: 'Forbidden' });
        }
        const accessToken = generateAccessToken(user._id);
        res.json({ token: accessToken });
      }
    );
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Logout user / clear cookie
// @route   POST /api/auth/logout
// @access  Public
const logoutUser = async (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(204);

  const refreshToken = cookies.jwt;

  try {
    const user = await User.findOne({ refreshToken });
    if (user) {
      user.refreshToken = '';
      await user.save();
    }
  } catch (error) {
    console.error(error);
  }

  res.clearCookie('jwt', { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' });
  res.status(200).json({ message: 'Logged out successfully' });
};

// @desc    Get user profile
// @route   GET /api/auth/me
// @access  Private
const getUserProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = {
  loginUser,
  refreshToken,
  logoutUser,
  getUserProfile,
};
