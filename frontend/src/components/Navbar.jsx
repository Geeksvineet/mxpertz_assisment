import { Link, useNavigate } from "react-router-dom";
import Cookies from "js-cookie";
import { jwtDecode } from "jwt-decode";

export default function Navbar() {
  const navigate = useNavigate();
  const token = Cookies.get("token");
  let role = null;

  // Decode JWT to get role
  if (token) {
    try {
      const decoded = jwtDecode(token);
      role = decoded.role; // 👈 Ensure your JWT payload contains 'role'
    } catch (err) {
      console.error("Invalid token:", err);
    }
  }

  const handleLogout = () => {
    Cookies.remove("token");
    navigate("/login");
  };

  return (
    <nav className="bg-blue-600 text-white p-4 flex justify-between items-center">
      <Link to="/" className="font-bold text-lg">
        🏥 Hospital System
      </Link>

      <div className="space-x-4 flex items-center">
        {/* Show different menu based on role */}
        {token ? (
          <>
            {role === "patient" && (
              <>
                <Link to="/doctors" className="hover:underline">
                  Doctors
                </Link>
                <Link to="/book" className="hover:underline">
                  Book Appointment
                </Link>
                <Link to="/patient-dashboard" className="hover:underline">
                  Dashboard
                </Link>
              </>
            )}

            {role === "doctor" && (
              <>
                <Link to="/doctor-dashboard" className="hover:underline">
                  Dashboard
                </Link>
              </>
            )}

            <button
              onClick={handleLogout}
              className="bg-red-500 px-3 py-1 rounded hover:bg-red-600"
            >
              Logout
            </button>
          </>
        ) : (
          <>
            {/* If not logged in */}
            <Link
              to="/login"
              className="bg-green-500 px-3 py-1 rounded hover:bg-green-600"
            >
              Login
            </Link>
            <Link
              to="/register"
              className="bg-white text-blue-600 px-3 py-1 rounded hover:bg-gray-100"
            >
              Register
            </Link>
          </>
        )}
      </div>
    </nav>
  );
}
