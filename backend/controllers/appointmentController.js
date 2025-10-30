const Appointment = require("../models/Appointment");

// Book appointment
exports.bookAppointment = async (req, res) => {
  try {
    const { patient, doctor, date, reason } = req.body;

    const newAppointment = await Appointment.create({
      patient,
      doctor,
      date,
      reason,
    });

    res.status(201).json({
      success: true,
      message: "Appointment booked successfully",
      appointment: newAppointment,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Cancel appointment
exports.cancelAppointment = async (req, res) => {
  try {
    const { id } = req.params;

    const appointment = await Appointment.findByIdAndDelete(id);

    if (!appointment)
      return res.status(404).json({ message: "Appointment not found" });

    res.status(200).json({
      success: true,
      message: "Appointment cancelled successfully",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Get all appointments (populate doctor & patient)
exports.getAllAppointments = async (req, res) => {
  try {
    const appointments = await Appointment.find()
      .populate("doctor", "name email role")
      .populate("patient", "name email role")
      .sort({ date: 1 });

    res.status(200).json(appointments);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.getDoctorAppointmentById = async (req, res) => {
  try {
    const { id } = req.params;
    const appointment = await Appointment.find({doctor:id})
      .populate("doctor", "name email role")
      .populate("patient", "name email role");

    if (!appointment)
      return res.status(404).json({ message: "Appointment not found" });

    res.status(200).json(appointment);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.getPatientAppointmentById = async (req, res) => {
  try {
    const { id } = req.params;

    const appointments = await Appointment.find({ patient: id })
      .populate("doctor", "name email role")
      .populate("patient", "name email role");

    if (!appointments || appointments.length === 0)
      return res.status(404).json({ message: "No appointments found for this patient" });

    res.status(200).json(appointments);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

