import axios from "axios";

const api = axios.create({
  baseURL: "https://mxpertz-assisment.onrender.com/api",
  withCredentials: true,
});

export default api;