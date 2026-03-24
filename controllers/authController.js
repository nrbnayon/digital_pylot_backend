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
      // Robust status check
      const status = (user.status || '').toString().trim().toLowerCase();
      
      if (status === 'pending') {
        return res.status(403).json({ message: 'Account is pending verification. Please verify your email first.' });
      }
      
      if (status !== 'active') {
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
      res.cookie('refreshToken', refreshToken, {
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
        accessToken: accessToken, 
        refreshToken: refreshToken, 
      });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Register a public user (Customer)
// @route   POST /api/auth/register
// @access  Public
const registerUser = async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Generate 6-digit OTP for verification
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expireDate = new Date(Date.now() + 10 * 60 * 1000); // 10 mins

    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role: 'customer',
      status: 'pending', // Force verification
      permissions: ['view_customer_portal'],
      resetPasswordOtp: otp,
      resetPasswordExpires: expireDate
    });

    if (user) {
      // Send email
      try {
        const sendEmail = require('../utils/sendEmail');
        await sendEmail({
          email: user.email,
          subject: 'Welcome to Digital Pylot - Verify Your Account',
          message: `Your verification OTP is ${otp}. It is valid for 10 minutes.`
        });
      } catch (err) {
        console.error('Email sending failed during registration:', err);
      }

      res.status(201).json({
         message: 'Registration successful. OTP sent to email.',
         email: user.email,
         status: 'pending'
      });
    } else {
      res.status(400).json({ message: 'Invalid user data' });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Refresh access token
// @route   POST /api/auth/refresh
// @access  Public
const refreshToken = async (req, res) => {
  const cookies = req.cookies;
  const bodyToken = req.body?.refresh_token;

  const rToken = bodyToken || cookies?.refreshToken;

  if (!rToken) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const user = await User.findOne({ refreshToken: rToken });
    if (!user) return res.status(403).json({ message: 'Forbidden' });

    jwt.verify(
      rToken,
      process.env.JWT_REFRESH_SECRET || 'refresh_secret',
      (err, decoded) => {
        if (err || user._id.toString() !== decoded.id) {
          return res.status(403).json({ message: 'Forbidden' });
        }
        const accessToken = generateAccessToken(user._id);
        const expires_at = Date.now() + 15 * 60 * 1000;
        
        res.json({ 
          message: "Token refreshed successfully",
          access_token: accessToken,
          expires_in: 15 * 60 * 1000,
          expires_at 
        });
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
  const rToken = cookies?.refreshToken;

  if (rToken) {
    try {
      const user = await User.findOne({ refreshToken: rToken });
      if (user) {
        user.refreshToken = '';
        await user.save();
      }
    } catch (error) {
      console.error(error);
    }
  }

  res.clearCookie('refreshToken', { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' });
  res.clearCookie('accessToken', { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' });
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

// @desc    Forgot Password
// @route   POST /api/auth/forgot-password
// @access  Public
const forgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'No user found with that email' });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expireDate = new Date(Date.now() + 10 * 60 * 1000); // 10 mins

    user.resetPasswordOtp = otp;
    user.resetPasswordExpires = expireDate;
    await user.save();

    // Send email
    const message = `Your password reset OTP is ${otp}. It is valid for 10 minutes.`;
    const sendEmail = require('../utils/sendEmail');
    await sendEmail({
      email: user.email,
      subject: 'Password Reset OTP',
      message
    });

    res.json({ message: 'OTP sent to email', success: true });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Verify OTP
// @route   POST /api/auth/verify-otp
// @access  Public
const verifyOtp = async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await User.findOne({ email, resetPasswordOtp: otp });
    
    if (!user) {
      return res.status(400).json({ message: 'Invalid OTP or Email' });
    }

    if (user.resetPasswordExpires < new Date()) {
      return res.status(400).json({ message: 'OTP has expired' });
    }

    // If they were pending (signup flow), activate them now
    if (user.status === 'pending') {
        user.status = 'active';
    }

    user.resetPasswordOtp = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'OTP verified successfully', verified: true });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Reset Password
// @route   POST /api/auth/reset-password
// @access  Public
const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    const user = await User.findOne({ email, resetPasswordOtp: otp });
    
    if (!user) return res.status(400).json({ message: 'Invalid OTP or Email' });
    if (user.resetPasswordExpires < new Date()) return res.status(400).json({ message: 'OTP has expired' });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    
    // reset OTP flags
    user.resetPasswordOtp = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Password reset successful', success: true });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = {
  loginUser,
  registerUser,
  refreshToken,
  logoutUser,
  getUserProfile,
  forgotPassword,
  verifyOtp,
  resetPassword
};
