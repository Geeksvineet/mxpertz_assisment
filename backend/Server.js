const express = require("express");
const cookieParser = require("cookie-parser");
const dotenv = require("dotenv");
const ConnectDb = require("./configuration/ConnectDb.js")
const cors = require("cors");

dotenv.config();

const authRoutes = require("./routes/authRoutes");
const appointmentRoutes = require("./routes/appointmentRoutes");

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "https://mxpertz-assisment-1.onrender.com", // React frontend
    credentials: true,
  })
);

app.get("/",(req,res)=>{
  res.send("<h1>Home Page</h1>")
})

app.use("/api/auth", authRoutes);
app.use("/api/appointments", appointmentRoutes);

const port = process.env.PORT || 4000;

ConnectDb().then(() => {
  app.listen(port, () => {
    console.log(`✅ Server is running at port ${port}`);
  });
}).catch((err) => {
  console.error("❌ Failed to connect to DB:", err);
});

