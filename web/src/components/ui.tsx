import { cloneElement, isValidElement, useEffect, useId, useRef } from "react";
import type { ButtonHTMLAttributes, ReactElement, ReactNode } from "react";

import { ApiError } from "../api/client";
import "./ui.css";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "quiet" | "danger";
};

export function Button({ variant, className, ...props }: ButtonProps) {
  const classes = ["button", variant ? `button--${variant}` : "", className ?? ""].join(" ").trim();
  return <button className={classes} {...props} />;
}

export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  children: ReactNode;
}) {
  const generatedID = useId();
  const hintID = hint ? `${generatedID}-hint` : undefined;
  const errorID = error ? `${generatedID}-error` : undefined;
  const describedBy = [hintID, errorID].filter(Boolean).join(" ") || undefined;
  const element = isValidElement(children) ? (children as ReactElement<Record<string, unknown>>) : null;
  const controlID = (element?.props.id as string | undefined) ?? generatedID;
  const control = element
    ? cloneElement(element, {
        id: controlID,
        "aria-describedby": describedBy,
        "aria-invalid": error ? true : element.props["aria-invalid"],
      })
    : children;
  return (
    <div className="field">
      <label htmlFor={controlID}>{label}</label>
      <div>{control}</div>
      {hint ? <p className="hint" id={hintID}>{hint}</p> : null}
      {error ? <p className="error" id={errorID}>{error}</p> : null}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <h2>{title}</h2>
      {children}
    </div>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <p className="spinner" role="status">
      {label}
    </p>
  );
}

/** ErrorNote turns an unknown thrown value into something readable. */
export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null;
  const message =
    error instanceof ApiError
      ? error.message
      : error instanceof SyntaxError
        ? "The server returned an unreadable response. Try again; if it continues, check the server or proxy logs."
        : error instanceof TypeError
          ? "Retune could not reach the server. Check the connection, then try again."
          : error instanceof Error
            ? error.message
            : String(error);
  return (
    <p className="note note--error" role="alert">
      {message}
    </p>
  );
}

export function SuccessNote({ children }: { children: ReactNode }) {
  return <div className="note note--success" role="status">{children}</div>;
}

/** HeldNote says a request is waiting for a second administrator. */
export function HeldNote() {
  return (
    <p className="note note--pending" role="status">
      Sent for approval. It happens once another administrator approves it on the Approvals page.
    </p>
  );
}

export function Dialog({
  title,
  open,
  onClose,
  children,
}: {
  title: string;
  open: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const titleID = useId();

  useEffect(() => {
    if (!open) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const dialog = dialogRef.current;
    if (dialog && !dialog.open) {
      if (typeof dialog.showModal === "function") dialog.showModal();
      else dialog.setAttribute("open", "");
    }
    return () => {
      if (dialog?.open && typeof dialog.close === "function") dialog.close();
      opener?.focus();
    };
  }, [open]);

  if (!open) return null;
  return (
    <dialog
      ref={dialogRef}
      className="dialog"
      aria-labelledby={titleID}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="dialog__surface" onClick={(event) => event.stopPropagation()}>
        <header>
          <h2 id={titleID}>{title}</h2>
          <Button variant="quiet" onClick={onClose} aria-label="Close dialog">
            <span aria-hidden="true">×</span>
          </Button>
        </header>
        {children}
      </div>
    </dialog>
  );
}
