import { Link, useNavigate } from "react-router-dom";
import Cookies from "js-cookie";

export default function LandingPage() {
  const navigate = useNavigate();
  const token = Cookies.get("token");

  const handleGetStarted = () => {
    if (token) navigate("/dashboard");
    else navigate("/login");
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-blue-100 flex flex-col">
      {/* MAIN HERO CONTENT */}
      <main className="flex flex-col md:flex-row items-center justify-center flex-grow px-8">
        <div className="max-w-xl text-center md:text-left space-y-6">
          <h1 className="text-4xl md:text-5xl font-bold text-blue-700 leading-tight">
            Manage Patients, Doctors & Appointments Effortlessly
          </h1>
          <p className="text-gray-700 text-lg">
            Our Hospital Management System helps you streamline patient
            appointments, doctor schedules, and records — all in one place.
          </p>
          <div className="space-x-3">
            <button
              onClick={handleGetStarted}
              className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition"
            >
              Get Started
            </button>
            <Link
              to="/doctors"
              className="bg-white text-blue-600 border border-blue-600 px-6 py-3 rounded-lg hover:bg-blue-50 transition"
            >
              View Doctors
            </Link>
          </div>
        </div>

        <img
          src="https://cdn-icons-png.flaticon.com/512/2966/2966486.png"
          alt="Hospital Illustration"
          className="w-80 mt-10 md:mt-0 md:ml-10 animate-fadeIn"
        />
      </main>

      {/* FOOTER */}
      <footer className="text-center p-4 text-gray-600 text-sm">
        © {new Date().getFullYear()} Hospital Management System. All rights reserved.
      </footer>
    </div>
  );
}
