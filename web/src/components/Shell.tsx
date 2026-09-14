import { NavLink } from "react-router-dom";
import type { ReactNode } from "react";

import { useSession } from "../session/SessionContext";
import { Button } from "./ui";
import "./Shell.css";

const LINKS = [
  { to: "/devices", label: "Devices" },
  { to: "/groups", label: "Groups" },
  { to: "/scripts", label: "Scripts" },
  { to: "/apps", label: "Apps" },
  { to: "/agent-versions", label: "Agent versions" },
  { to: "/profiles", label: "Profiles" },
  { to: "/commands", label: "Commands" },
  { to: "/tokens", label: "Enrollment" },
  { to: "/audit", label: "Audit" },
  { to: "/admins", label: "Admins" },
];

export function Shell({ children }: { children: ReactNode }) {
  const { admin, signOut } = useSession();
  return (
    <div className="shell">
      <aside className="rail">
        <div className="rail__mark">Retune</div>
        <nav>
          {LINKS.map((link) => (
            <NavLink key={link.to} to={link.to}>
              {link.label}
            </NavLink>
          ))}
        </nav>
        <div className="rail__footer">
          <span className="mono">{admin?.email}</span>
          {admin?.role === "read_only" ? <span>Read-only access</span> : null}
          <Button variant="quiet" onClick={() => void signOut()}>
            Sign out
          </Button>
        </div>
      </aside>
      <main className="content">{children}</main>
    </div>
  );
}
