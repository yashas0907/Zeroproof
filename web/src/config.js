// Single source of truth for the backend URL (Java Spring Boot API).
// Override with VITE_API_URL in web/.env.local, e.g. VITE_API_URL=http://localhost:3000
export const API_URL = (import.meta.env.VITE_API_URL || "http://localhost:3000").replace(/\/+$/, "");
