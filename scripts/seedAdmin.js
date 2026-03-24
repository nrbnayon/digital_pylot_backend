require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const connectDB = require('../config/db');

const seedAdmin = async () => {
  await connectDB();

  try {
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@gmail.com';
    const adminName = process.env.ADMIN_NAME || 'Admin';
    const adminPassword = process.env.ADMIN_PASSWROD || 'admin';

    let user = await User.findOne({ email: adminEmail });

    if (!user) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(adminPassword, salt);

      // Give admin all atoms for our system
      const allAtoms = [
        "view_dashboard", 
        "manage_jobs", "view_jobs", 
        "view_applications", "manage_applications", 
        "manage_users", 
        "manage_settings", "manage_categories",
        "view_notifications",
        "view_customer_portal"
      ];

      user = await User.create({
        name: adminName,
        email: adminEmail,
        password: hashedPassword,
        role: 'admin',
        status: 'active',
        permissions: allAtoms
      });
      console.log('Admin user seeded properly');
    } else {
      console.log('Admin user already exists');
    }
    
    process.exit(0);
  } catch (error) {
    console.error('Error seeding admin', error);
    process.exit(1);
  }
};

seedAdmin();
