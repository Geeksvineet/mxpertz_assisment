const express = require("express");
const {
  registerUser,
  loginUser,
  logoutUser,
  getUsersByRole,
} = require("../controllers/authController");

const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/logout", logoutUser);
router.get("/users/:role", getUsersByRole);

module.exports = router;
