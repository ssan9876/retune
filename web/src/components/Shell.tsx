import { useEffect, useMemo, useRef, useState } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import type { ReactNode } from "react";

import { useSession } from "../session/SessionContext";
import { Icon } from "./Icon";
import "./Shell.css";

type Link = { to: string; label: string; icon: string };
type Section = { heading?: string; links: Link[] };

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
      { to: "/tokens", label: "Enrollment", icon: "key" },
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
    ],
  },
  {
    heading: "Endpoint security",
    links: [{ to: "/compliance", label: "Compliance policies", icon: "shield" }],
  },
  {
    heading: "Tenant administration",
    links: [
      { to: "/alerts", label: "Alerts", icon: "bell" },
      { to: "/admins", label: "Admins", icon: "person" },
      { to: "/audit", label: "Audit log", icon: "list" },
    ],
  },
];

const ALL_LINKS = SECTIONS.flatMap((s) => s.links);

/** breadcrumbFor names where you are, the way the admin centre's own
 * breadcrumb does: the section this page sits in, then the page. */
function breadcrumbFor(pathname: string): string[] {
  const section = SECTIONS.find((s) => s.links.some((l) => matches(l.to, pathname)));
  const link = ALL_LINKS.find((l) => matches(l.to, pathname));
  if (!link || link.to === "/") return ["Home"];
  const crumbs = ["Home"];
  if (section?.heading) crumbs.push(section.heading);
  crumbs.push(link.label);
  return crumbs;
}

function matches(to: string, pathname: string): boolean {
  return to === "/" ? pathname === "/" : pathname === to || pathname.startsWith(to + "/");
}

/** Search jumps between pages rather than querying the fleet: there is no
 * search endpoint behind it, and a box that looks like one and finds nothing
 * would be worse than none. Enter opens the first match. */
function NavSearch({ onGo }: { onGo: (to: string) => void }) {
  const [query, setQuery] = useState("");
  const hits = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    return ALL_LINKS.filter((l) => l.label.toLowerCase().includes(q)).slice(0, 6);
  }, [query]);

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
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && hits.length > 0) go(hits[0].to);
          if (e.key === "Escape") setQuery("");
        }}
      />
      {hits.length > 0 ? (
        <ul className="topbar__results">
          {hits.map((l) => (
            <li key={l.to}>
              <button type="button" onMouseDown={() => go(l.to)}>
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
  const initials = (admin?.email ?? "?").slice(0, 2).toUpperCase();

  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  return (
    <div className="topbar__account" ref={ref}>
      <button
        type="button"
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
              {admin?.role === "read_only" ? "Read-only access" : "Administrator"}
            </span>
          </div>
          <button type="button" role="menuitem" onClick={() => void signOut()}>
            Sign out
          </button>
        </div>
      ) : null}
    </div>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const { admin } = useSession();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [collapsed, setCollapsed] = useState(false);
  const crumbs = breadcrumbFor(pathname);

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
        <NavSearch onGo={navigate} />
        <div className="topbar__tools">
          {admin?.role === "read_only" ? <span className="topbar__badge">Read-only</span> : null}
          <AccountMenu />
        </div>
      </header>

      <aside className="rail">
        <nav aria-label="Main">
          {SECTIONS.map((section, i) => (
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
      </aside>

      <main className="content">
        <nav className="crumbs" aria-label="Breadcrumb">
          {crumbs.map((crumb, i) => (
            <span key={crumb}>
              {i > 0 ? <span className="crumbs__sep">›</span> : null}
              {crumb}
            </span>
          ))}
        </nav>
        {children}
      </main>
    </div>
  );
}
