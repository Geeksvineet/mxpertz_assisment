import { useState } from "react";
import api from "../api/axiosInstance";
import { useNavigate } from "react-router-dom";

export default function Register() {
  const [form, setForm] = useState({ name: "", username: "", email: "", password: "", role: "patient" });
  const navigate = useNavigate();

  const handleChange = (e) =>
    setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await api.post("/auth/register", form);
      alert("Registered successfully!");
      navigate("/login");
    } catch (err) {
      alert(err.response?.data?.message || "Error registering");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <form
        onSubmit={handleSubmit}
        className="bg-white p-6 rounded-lg shadow-lg w-96 space-y-4"
      >
        <h2 className="text-2xl font-bold text-center">Register</h2>
        <input name="name" onChange={handleChange} placeholder="Full Name" className="border p-2 w-full" required />
        <input name="username" onChange={handleChange} placeholder="Username" className="border p-2 w-full" required />
        <input name="email" type="email" onChange={handleChange} placeholder="Email" className="border p-2 w-full" required />
        <input name="password" type="password" onChange={handleChange} placeholder="Password" className="border p-2 w-full" required />
        <select name="role" onChange={handleChange} className="border p-2 w-full">
          <option value="patient">Patient</option>
          <option value="doctor">Doctor</option>
        </select>
        <button type="submit" className="bg-blue-600 text-white w-full p-2 rounded">
          Register
        </button>
      </form>
    </div>
  );
}
