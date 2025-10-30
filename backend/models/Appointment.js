const mongoose = require("mongoose");

const appointmentSchema = new mongoose.Schema(
  {
    patient: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "Patient is required"],
    },
    doctor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "Doctor is required"],
    },
    reason: {
      type: String,
      trim: true,
      default: "",
    },
    date: {
      type: Date,
      required: [true, "Appointment date is required"],
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Appointment", appointmentSchema);
