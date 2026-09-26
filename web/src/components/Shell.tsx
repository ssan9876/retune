import { useEffect, useId, useMemo, useRef, useState } from "react";
import { Link as RouterLink, NavLink, useLocation, useNavigate } from "react-router-dom";
import type { ReactNode } from "react";

import { api } from "../api/client";
import type { ServerInfo } from "../api/serverupdate";
import { useSession } from "../session/SessionContext";
import { Icon } from "./Icon";
import "./Shell.css";

/** fleet marks pages about the whole fleet rather than devices, which an
 * admin limited to some device groups cannot use; the server refuses them, so
 * the nav does not offer them. */
type Link = { to: string; label: string; icon: string; fleet?: boolean };
type Section = { heading?: string; links: Link[] };
type Crumb = { label: string; to?: string };

/** The nav is grouped the way the Intune admin centre groups its own: the
 * fleet first, then the things pushed to it, then what judges it, then the
 * tenant's own administration. Labels are the page's name in the product, not
 * the route, which is why "Compliance policies" points at /compliance. */
const SECTIONS: Section[] = [
  { links: [{ to: "/", label: "Home", icon: "home" }] },
  {
    heading: "Devices",
    links: [
      { to: "/devices", label: "All devices", icon: "device" },
      { to: "/groups", label: "Groups", icon: "group" },
      { to: "/tokens", label: "Enrollment", icon: "key", fleet: true },
      { to: "/provisioning", label: "Provisioning", icon: "check", fleet: true },
      { to: "/commands", label: "Commands", icon: "terminal" },
    ],
  },
  {
    heading: "Deployment",
    links: [
      { to: "/apps", label: "Apps", icon: "app" },
      { to: "/scripts", label: "Scripts", icon: "script" },
      { to: "/profiles", label: "Configuration profiles", icon: "profile" },
      { to: "/agent-versions", label: "Agent versions", icon: "update" },
      { to: "/maintenance-windows", label: "Maintenance windows", icon: "clock" },
    ],
  },
  {
    heading: "Endpoint security",
    links: [{ to: "/compliance", label: "Compliance policies", icon: "shield" }],
  },
  {
    heading: "Tenant administration",
    links: [
      { to: "/approvals", label: "Approvals", icon: "check", fleet: true },
      { to: "/alerts", label: "Alerts", icon: "bell", fleet: true },
      { to: "/admins", label: "Admins", icon: "person", fleet: true },
      { to: "/api-tokens", label: "API tokens", icon: "key", fleet: true },
      { to: "/reports", label: "Scheduled reports", icon: "mail", fleet: true },
      { to: "/audit", label: "Audit log", icon: "list", fleet: true },
      { to: "/server-update", label: "Server update", icon: "update", fleet: true },
    ],
  },
];

const ALL_LINKS = SECTIONS.flatMap((s) => s.links);

/** breadcrumbFor names where you are, the way the admin centre's own
 * breadcrumb does: the section this page sits in, then the page. */
function breadcrumbFor(pathname: string): Crumb[] {
  if (pathname.startsWith("/devices/")) {
    return [
      { label: "Home", to: "/" },
      { label: "Devices" },
      { label: "All devices", to: "/devices" },
      { label: "Device details" },
    ];
  }
  if (pathname.startsWith("/remote-sessions/")) {
    return [{ label: "Home", to: "/" }, { label: "Devices", to: "/devices" }, { label: "Remote session" }];
  }
  const section = SECTIONS.find((s) => s.links.some((l) => matches(l.to, pathname)));
  const link = ALL_LINKS.find((l) => matches(l.to, pathname));
  if (!link || link.to === "/") return [{ label: "Home" }];
  const crumbs: Crumb[] = [{ label: "Home", to: "/" }];
  if (section?.heading) crumbs.push({ label: section.heading });
  crumbs.push({ label: link.label });
  return crumbs;
}

function matches(to: string, pathname: string): boolean {
  return to === "/" ? pathname === "/" : pathname === to || pathname.startsWith(to + "/");
}

/** Search jumps between pages rather than querying the fleet: there is no
 * search endpoint behind it, and a box that looks like one and finds nothing
 * would be worse than none. Enter opens the first match. */
/** sectionsFor is the nav an admin can use: all of it, or without the fleet
 * pages for an admin limited to some device groups. */
function sectionsFor(scoped: boolean): Section[] {
  if (!scoped) return SECTIONS;
  return SECTIONS.map((s) => ({ ...s, links: s.links.filter((l) => !l.fleet) })).filter((s) => s.links.length > 0);
}

function NavSearch({ onGo, links }: { onGo: (to: string) => void; links: Link[] }) {
  const [query, setQuery] = useState("");
  const resultsID = useId();
  const hits = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    return links.filter((l) => l.label.toLowerCase().includes(q)).slice(0, 6);
  }, [query, links]);

  function go(to: string) {
    setQuery("");
    onGo(to);
  }

  return (
    <div className="topbar__search">
      <Icon name="search" />
      <input
        type="search"
        value={query}
        placeholder="Search pages"
        aria-label="Search pages"
        aria-expanded={hits.length > 0}
        aria-controls={resultsID}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && hits.length > 0) go(hits[0].to);
          if (e.key === "Escape") setQuery("");
        }}
      />
      {hits.length > 0 ? (
        <ul className="topbar__results" id={resultsID}>
          {hits.map((l) => (
            <li key={l.to}>
              <button type="button" onClick={() => go(l.to)}>
                <Icon name={l.icon} /> {l.label}
              </button>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function AccountMenu() {
  const { admin, signOut } = useSession();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const signOutRef = useRef<HTMLButtonElement>(null);
  const initials = (admin?.email ?? "?").slice(0, 2).toUpperCase();

  useEffect(() => {
    if (!open) return;
    signOutRef.current?.focus();
    function onDown(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    }
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className="topbar__account" ref={ref}>
      <button
        type="button"
        ref={triggerRef}
        className="topbar__avatar"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Account: ${admin?.email ?? ""}`}
        onClick={() => setOpen((v) => !v)}
      >
        {initials}
      </button>
      {open ? (
        <div className="topbar__menu" role="menu">
          <div className="topbar__menu-head">
            <span className="topbar__menu-email">{admin?.email}</span>
            <span className="topbar__menu-role">
              {admin?.role === "read_only"
                ? "Read-only access"
                : admin?.role === "helpdesk"
                  ? "Helpdesk"
                  : "Administrator"}
            </span>
          </div>
          <button ref={signOutRef} type="button" role="menuitem" onClick={() => void signOut()}>
            Sign out
          </button>
        </div>
      ) : null}
    </div>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const { admin } = useSession();
  const sections = sectionsFor(admin?.scope != null);
  const links = sections.flatMap((section) => section.links);
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [collapsed, setCollapsed] = useState(false);
  const crumbs = breadcrumbFor(pathname);
  const [server, setServer] = useState<ServerInfo | null>(null);
  useEffect(() => {
    // The version in the rail and, for an administrator, the banner when a
    // newer release is out. Neither is worth an error if it cannot be read.
    api
      .get<ServerInfo>("/server")
      .then(setServer)
      .catch(() => undefined);
  }, []);
  const offerUpdate =
    admin?.role === "admin" &&
    admin.scope == null &&
    server?.update_available &&
    server.latest &&
    pathname !== "/server-update";

  return (
    <div className={`shell${collapsed ? " shell--collapsed" : ""}`}>
      <header className="topbar">
        <button
          type="button"
          className="topbar__burger"
          aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
          aria-expanded={!collapsed}
          onClick={() => setCollapsed((v) => !v)}
        >
          <Icon name="menu" />
        </button>
        <span className="topbar__brand">
          <Icon name="mark" />
          Retune
        </span>
        <span className="topbar__suite">admin center</span>
        <NavSearch links={links} onGo={navigate} />
        <div className="topbar__tools">
          {admin?.role === "read_only" ? <span className="topbar__badge">Read-only</span> : null}
          <AccountMenu />
        </div>
      </header>

      <aside className="rail">
        <nav aria-label="Main">
          {sections.map((section, i) => (
            <div className="rail__section" key={section.heading ?? i}>
              {section.heading ? <div className="rail__heading">{section.heading}</div> : null}
              {section.links.map((link) => (
                <NavLink key={link.to} to={link.to} end={link.to === "/"} title={link.label}>
                  <Icon name={link.icon} />
                  <span className="rail__label">{link.label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        {server ? <div className="rail__version">Retune {server.version}</div> : null}
      </aside>

      <main className="content">
        <nav className="crumbs" aria-label="Breadcrumb">
          {crumbs.map((crumb, i) => (
            <span key={`${crumb.label}-${i}`}>
              {i > 0 ? <span className="crumbs__sep" aria-hidden="true">â€º</span> : null}
              {crumb.to ? <RouterLink to={crumb.to}>{crumb.label}</RouterLink> : crumb.label}
            </span>
          ))}
        </nav>
        {offerUpdate && server?.latest ? (
          <div className="update-banner" role="status">
            <span>
              Retune {server.latest.version} is available — you run {server.version}.
            </span>
            <RouterLink to="/server-update">Review and update</RouterLink>
          </div>
        ) : null}
        {children}
      </main>
    </div>
  );
}
