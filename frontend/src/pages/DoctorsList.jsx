import { useEffect, useState } from "react";
import axiosInstance from "../api/axiosInstance";

const DoctorsList = () => {
  const [doctors, setDoctors] = useState([]);

  useEffect(() => {
    const fetchDoctors = async () => {
      const { data } = await axiosInstance.get("auth/users/doctor");
      setDoctors(data);
    };
    fetchDoctors();
  }, []);

  return (
    <div className="p-6">
      <h1 className="text-2xl font-semibold mb-4">Doctors</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {doctors.map((doc) => (
          <div key={doc._id} className="border p-4 rounded shadow">
            <h2 className="font-bold">{doc.name}</h2>
            <p>{doc.email}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default DoctorsList;
