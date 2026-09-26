import { Navigate, Route, Routes } from "react-router-dom";

import { Shell } from "./components/Shell";
import { Button, ErrorNote, Spinner } from "./components/ui";
import Admins from "./pages/Admins";
import ApiTokens from "./pages/ApiTokens";
import AgentVersions from "./pages/AgentVersions";
import Apps from "./pages/Apps";
import Alerts from "./pages/Alerts";
import Approvals from "./pages/Approvals";
import Audit from "./pages/Audit";
import Commands from "./pages/Commands";
import Compliance from "./pages/Compliance";
import DeviceDetail from "./pages/DeviceDetail";
import Devices from "./pages/Devices";
import Groups from "./pages/Groups";
import Login from "./pages/Login";
import MaintenanceWindows from "./pages/MaintenanceWindows";
import Overview from "./pages/Overview";
import Profiles from "./pages/Profiles";
import Provisioning from "./pages/Provisioning";
import RemoteSession from "./pages/RemoteSession";
import Reports from "./pages/Reports";
import Scripts from "./pages/Scripts";
import ServerUpdate from "./pages/ServerUpdate";
import Tokens from "./pages/Tokens";
import { useSession } from "./session/SessionContext";

export default function App() {
  const { admin, loading, startupError, retryStartup } = useSession();
  if (loading) return <Spinner label="Loading the console…" />;
  if (!admin && startupError) {
    return (
      <main className="service-unavailable">
        <div>
          <h1>Retune is unavailable</h1>
          <p>The console could not reach the Retune server. Your session and device data have not been changed.</p>
          <ErrorNote error={startupError} />
          <Button variant="primary" onClick={retryStartup}>Try again</Button>
        </div>
      </main>
    );
  }
  if (!admin) return <Login />;
  return (
    <Shell>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/devices" element={<Devices />} />
        <Route path="/devices/:id" element={<DeviceDetail />} />
        <Route path="/remote-sessions/:id" element={<RemoteSession />} />
        <Route path="/groups" element={<Groups />} />
        <Route path="/scripts" element={<Scripts />} />
        <Route path="/apps" element={<Apps />} />
        <Route path="/agent-versions" element={<AgentVersions />} />
        <Route path="/profiles" element={<Profiles />} />
        <Route path="/maintenance-windows" element={<MaintenanceWindows />} />
        <Route path="/compliance" element={<Compliance />} />
        <Route path="/commands" element={<Commands />} />
        <Route path="/tokens" element={<Tokens />} />
        <Route path="/provisioning" element={<Provisioning />} />
        <Route path="/approvals" element={<Approvals />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/admins" element={<Admins />} />
        <Route path="/api-tokens" element={<ApiTokens />} />
        <Route path="/server-update" element={<ServerUpdate />} />
        <Route path="*" element={<Navigate to="/devices" replace />} />
      </Routes>
    </Shell>
  );
}
