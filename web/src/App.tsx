import { Navigate, Route, Routes } from "react-router-dom";

import { Shell } from "./components/Shell";
import { Spinner } from "./components/ui";
import Admins from "./pages/Admins";
import AgentVersions from "./pages/AgentVersions";
import Apps from "./pages/Apps";
import Audit from "./pages/Audit";
import Commands from "./pages/Commands";
import DeviceDetail from "./pages/DeviceDetail";
import Devices from "./pages/Devices";
import Groups from "./pages/Groups";
import Login from "./pages/Login";
import Profiles from "./pages/Profiles";
import Scripts from "./pages/Scripts";
import Tokens from "./pages/Tokens";
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
        <Route path="/devices/:id" element={<DeviceDetail />} />
        <Route path="/groups" element={<Groups />} />
        <Route path="/scripts" element={<Scripts />} />
        <Route path="/apps" element={<Apps />} />
        <Route path="/agent-versions" element={<AgentVersions />} />
        <Route path="/profiles" element={<Profiles />} />
        <Route path="/commands" element={<Commands />} />
        <Route path="/tokens" element={<Tokens />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/admins" element={<Admins />} />
        <Route path="*" element={<Navigate to="/devices" replace />} />
      </Routes>
    </Shell>
  );
}
