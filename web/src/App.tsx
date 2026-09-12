import { useSession } from "./session/SessionContext";

export default function App() {
  const { admin, loading } = useSession();
  if (loading) return <p role="status">Loading the console…</p>;
  return <h1>{admin ? `Signed in as ${admin.email}` : "Retune"}</h1>;
}
