import { useEffect, useState } from "react";
import Cookies from "js-cookie";
import { jwtDecode } from "jwt-decode";
import api from "../api/axiosInstance";

export default function PatientDashboard() {
  const [user, setUser] = useState("");
  const [appointments, setAppointments] = useState([]);

  useEffect(() => {
    const token = Cookies.get("token");
    if (!token) {
      console.warn("No token found, redirect to login if needed.");
      return;
    }

    try {
      const decoded = jwtDecode(token);
      const userId = decoded.id || decoded._id;
      const username = decoded.username || decoded.name || "User";
      setUser(username);

      // ✅ Fetch appointments for this patient
      api
        .get(`/appointments/doctor/${userId}`)
        .then((res) => {
          // handle both cases: res.data.data or res.data directly
          const data = res.data.data || res.data;
          setAppointments(Array.isArray(data) ? data : []);
        })
        .catch((err) => {
          console.error("Error fetching appointments:", err);
        });
    } catch (error) {
      console.error("Invalid token:", error);
      Cookies.remove("token");
    }
  }, []);


  return (
    <div className="p-6 max-w-5xl mx-auto">
      {/* ✅ Patient Info */}
      <div className="bg-white shadow-md rounded-lg p-6 mb-6">
        <h2 className="text-2xl font-bold mb-2">Welcome, {user}</h2>
      </div>

      {/* ✅ Appointments List */}
      <div className="bg-white shadow-md rounded-lg p-6">
        <h2 className="text-xl font-semibold mb-4">My Appointments</h2>

        {appointments.length === 0 ? (
          <p className="text-gray-500">No appointments found.</p>
        ) : (
          <table className="w-full border">
            <thead>
              <tr className="bg-gray-100 text-left">
                <th className="border p-2">#</th>
                <th className="border p-2">Doctor</th>
                <th className="border p-2">Reason</th>
                <th className="border p-2">Date</th>
              </tr>
            </thead>
            <tbody>
              {appointments.map((apt, i) => (
                <tr key={apt._id} className="hover:bg-gray-50">
                  <td className="border p-2">{i + 1}</td>
                  <td className="border p-2">{apt.doctor?.name || "N/A"}</td>
                  <td className="border p-2">{apt.reason || "—"}</td>
                  <td className="border p-2">
                    {new Date(apt.date).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
