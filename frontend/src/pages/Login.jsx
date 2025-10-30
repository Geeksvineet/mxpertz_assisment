import { useState } from "react";
import api from "../api/axiosInstance";
import Cookies from "js-cookie";
import { useNavigate } from "react-router-dom";
import { jwtDecode } from "jwt-decode";

export default function Login() {
  const [form, setForm] = useState({ username: "", password: "" });
  const navigate = useNavigate();

  const handleChange = (e) =>
    setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await api.post("/auth/login", form);
      const token = res.data.token;

      // Save token in cookies
      Cookies.set("token", token, { expires: 1 });

      // Decode token to get role
      const decoded = jwtDecode(token);
      const userRole = decoded.role;

      alert("Login successful!");

      // Navigate based on role
      if (userRole === "patient") {
        navigate("/patient-dashboard");
      } else if (userRole === "doctor") {
        navigate("/doctor-dashboard");
      } else {
        navigate("/dashboard");
      }
    } catch (err) {
      console.error("Login error:", err);
      alert(err.response?.data?.message || "Login failed");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <form
        onSubmit={handleSubmit}
        className="bg-white p-6 rounded-lg shadow-lg w-96 space-y-4"
      >
        <h2 className="text-2xl font-bold text-center">Login</h2>
        <input
          name="username"
          onChange={handleChange}
          placeholder="Username"
          className="border p-2 w-full"
          required
        />
        <input
          name="password"
          type="password"
          onChange={handleChange}
          placeholder="Password"
          className="border p-2 w-full"
          required
        />
        <button
          type="submit"
          className="bg-blue-600 text-white w-full p-2 rounded hover:bg-blue-700"
        >
          Login
        </button>
      </form>
    </div>
  );
}
