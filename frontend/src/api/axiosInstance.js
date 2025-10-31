import axios from "axios";

const api = axios.create({
  baseURL: "https://mxpertz-assisment.onrender.com/api",
  withCredentials: true,
});

api.interceptors.request.use(
  (config) => {
    const token = Cookies.get("token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    } else {
      console.warn("No token found in cookies");
    }
    return config;
  },
  (error) => Promise.reject(error)
);

export default api;