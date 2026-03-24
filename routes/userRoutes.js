const express = require('express');
const router = express.Router();
const { getUsers, createUser, updateUser, deleteUser } = require('../controllers/userController');
const { protect, requirePermission } = require('../middleware/authMiddleware');

// Base requirements: Any user making changes needs manage_users permission
router.route('/')
  .get(protect, requirePermission('users:read'), getUsers)
  .post(protect, requirePermission('users:write'), createUser);

router.route('/:id')
  .put(protect, requirePermission('users:write'), updateUser)
  .delete(protect, requirePermission('users:delete'), deleteUser);

module.exports = router;
