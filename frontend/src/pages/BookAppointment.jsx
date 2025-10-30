import { useState, useEffect } from "react";
import api from "../api/axiosInstance";
import Cookies from "js-cookie";
import { jwtDecode } from "jwt-decode";
import { useNavigate } from "react-router-dom";

export default function BookAppointment() {
  const navigate = useNavigate();
  const [doctors, setDoctors] = useState([]);
  const [form, setForm] = useState({
    patient: "",
    doctor: "",
    date: "",
    reason: "",
  });

  // Decode patient ID from JWT
  useEffect(() => {
    const token = Cookies.get("token");
    if (token) {
      try {
        const decoded = jwtDecode(token);
        setForm((prev) => ({ ...prev, patient: decoded.id }));
      } catch (err) {
        console.error("Invalid token:", err);
      }
    }
  }, []);

  // Fetch doctors
  useEffect(() => {
    api
      .get("/auth/users/doctor")
      .then((res) => setDoctors(res.data))
      .catch((err) => console.error(err));
  }, []);

  const handleChange = (e) =>
    setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await api.post("/appointments/book", form);
      alert("Appointment booked successfully!");
      setForm({ patient: form.patient, doctor: "", date: "", reason: "" });
      navigate("/patient-dashboard");
    } catch (err) {
      alert(err.response?.data?.message || "Error booking appointment");
    }
  };

  return (
    <div className="p-6 max-w-lg mx-auto bg-white shadow-lg rounded-lg">
      <h2 className="text-2xl font-bold mb-4 text-center">Book Appointment</h2>
      <form onSubmit={handleSubmit} className="space-y-3">
        <select
          name="doctor"
          onChange={handleChange}
          className="border p-2 w-full rounded"
          required
        >
          <option value="">Select Doctor</option>
          {doctors.map((doc) => (
            <option key={doc._id} value={doc._id}>
              {doc.name}
            </option>
          ))}
        </select>

        <input
          name="date"
          type="datetime-local"
          onChange={handleChange}
          value={form.date}
          className="border p-2 w-full rounded"
          required
        />

        <textarea
          name="reason"
          onChange={handleChange}
          value={form.reason}
          placeholder="Reason for appointment"
          className="border p-2 w-full rounded"
          rows="3"
          required
        />

        <button
          type="submit"
          className="bg-blue-600 text-white w-full p-2 rounded hover:bg-blue-700 transition"
        >
          Book Appointment
        </button>
      </form>
    </div>
  );
}
