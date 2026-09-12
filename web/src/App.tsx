import { Navigate, Route, Routes } from "react-router-dom";

import { Shell } from "./components/Shell";
import { Spinner } from "./components/ui";
import Devices from "./pages/Devices";
import Login from "./pages/Login";
import { useSession } from "./session/SessionContext";

export default function App() {
  const { admin, loading } = useSession();
  if (loading) return <Spinner label="Loading the console…" />;
  if (!admin) return <Login />;
  return (
    <Shell>
      <Routes>
        <Route path="/" element={<Navigate to="/devices" replace />} />
        <Route path="/devices" element={<Devices />} />
        <Route path="*" element={<Navigate to="/devices" replace />} />
      </Routes>
    </Shell>
  );
}
