const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

// Register Patient or Doctor
exports.registerUser = async (req, res) => {
  try {
    const { name, username, email, password, role } = req.body;

    // check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "Email already registered" });

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      name,
      username,
      email,
      password: hashedPassword,
      role,
    });

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      user: { id: newUser._id, name: newUser.name, role: newUser.role },
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Login & Authenticate User
exports.loginUser = async (req, res) => {
  try {
    const { username, password } = req.body;

    // check if user exists
    const user = await User.findOne({ username });
    if (!user)
      return res.status(400).json({ message: "Invalid username" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid password" });

    // create jwt token
    const token = jwt.sign(
      { id: user._id, role: user.role, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    // store token in cookie
    res
      .cookie("token", token, {
        httpOnly: false,
        secure: false,
        sameSite: "Lax",
        maxAge: 24 * 60 * 60 * 1000, // 1 day
      })
      .status(200)
      .json({
        success: true,
        message: "Login successful",
        token,
        user: { id: user._id, name: user.name, role: user.role },
      });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Logout user
exports.logoutUser = async (req, res) => {
  try {
    res.clearCookie("token");
    res.status(200).json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Get all patients / doctors
exports.getUsersByRole = async (req, res) => {
  try {
    const { role } = req.params; // role=doctor or patient
    const users = await User.find({ role }).select("-password");
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
