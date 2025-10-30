import { BrowserRouter, Routes, Route } from "react-router-dom";
import Navbar from "./components/Navbar";
import Login from "./pages/Login";
import Register from "./pages/Register";
import BookAppointment from "./pages/BookAppointment";
import ProtectedRoute from "./components/ProtectedRoute";
import DoctorsList from "./pages/DoctorsList";
import LandingPage from "./pages/LandingPage";
import PatientDashboard from "./pages/PatientDashboard";
import DoctorDashboard from "./pages/DoctorDashboard";

export default function App() {
  return (
    <BrowserRouter>
      <Navbar />
      <Routes>
        <Route path="/" element={<LandingPage />} /> 
        <Route path="/register" element={<Register />} />
        <Route path="/login" element={<Login />} />
        <Route path="/doctors" element={<DoctorsList/>}/>
        <Route
          path="/book"
          element={
            <ProtectedRoute>
              <BookAppointment />
            </ProtectedRoute>
          }
        />
        <Route
          path="/patient-dashboard"
          element={
            <ProtectedRoute>
              <PatientDashboard/>
            </ProtectedRoute>
          }
        />
        <Route
          path="/doctor-dashboard"
          element={
            <ProtectedRoute>
              <DoctorDashboard/>
            </ProtectedRoute>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
