const express = require("express");
const {
  bookAppointment,
  cancelAppointment,
  getAllAppointments,
  getDoctorAppointmentById,
  getPatientAppointmentById,
} = require("../controllers/appointmentController");

const { protect } = require("../middlewares/authMiddleware.js");

const router = express.Router();

router.post("/book", protect, bookAppointment);
router.delete("/cancel/:id", protect, cancelAppointment);
router.get("/all", protect, getAllAppointments);
router.get("/doctor/:id", protect, getDoctorAppointmentById);
router.get("/patient/:id", protect, getPatientAppointmentById);

module.exports = router;
