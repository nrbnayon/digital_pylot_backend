const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { 
    type: String, 
    enum: ['Admin', 'Manager', 'Agent', 'Customer'], 
    default: 'Customer' 
  },
  status: { 
    type: String, 
    enum: ['Active', 'Suspended', 'Banned'], 
    default: 'Active' 
  },
  managedBy: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    default: null 
  },
  permissions: [{ type: String }],
  avatar: { type: String, default: '' },
  phone: { type: String, default: '' },
  location: { type: String, default: '' },
  refreshToken: { type: String, default: '' },
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
