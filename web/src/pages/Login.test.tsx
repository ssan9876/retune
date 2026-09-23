import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../api/client";
import Login from "./Login";

const signIn = vi.fn();
let needsSetup = false;
let sso: string | null = null;
let localLogin = true;

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({
    admin: null,
    loading: false,
    needsSetup,
    sso,
    localLogin,
    canWrite: false,
    signIn,
    signOut: vi.fn(),
  }),
}));

beforeEach(() => {
  signIn.mockReset();
  needsSetup = false;
  sso = null;
  localLogin = true;
  window.history.replaceState(null, "", "/");
});

describe("Login", () => {
  it("signs in with an email and password", async () => {
    signIn.mockResolvedValue(undefined);
    render(<Login />);

    await userEvent.type(screen.getByLabelText("Email"), "ops@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "correct horse battery");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(signIn).toHaveBeenCalledWith("ops@example.com", "correct horse battery", "");
    expect(screen.queryByLabelText("Authenticator code")).not.toBeInTheDocument();
  });

  it("asks for the authenticator code when the server requires one", async () => {
    signIn.mockRejectedValueOnce(new ApiError(401, "totp_required", "enter your authenticator code"));
    render(<Login />);

    await userEvent.type(screen.getByLabelText("Email"), "ops@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "correct horse battery");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    const code = await screen.findByLabelText("Authenticator code");
    signIn.mockResolvedValueOnce(undefined);
    await userEvent.type(code, "123456");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(signIn).toHaveBeenLastCalledWith("ops@example.com", "correct horse battery", "123456");
  });

  it("shows why a sign-in failed", async () => {
    signIn.mockRejectedValue(new ApiError(401, "invalid_credentials", "invalid email or password"));
    render(<Login />);
    await userEvent.type(screen.getByLabelText("Email"), "ops@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "nope");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("invalid email or password");
  });

  it("tells a new operator how to create the first account", () => {
    needsSetup = true;
    render(<Login />);
    expect(screen.getByText(/bootstrap-admin/)).toBeInTheDocument();
  });

  it("offers single sign-on beside the password form", () => {
    sso = "Sign in with Contoso";
    render(<Login />);
    const link = screen.getByRole("link", { name: "Sign in with Contoso" });
    expect(link).toHaveAttribute("href", "/api/admin/v1/oidc/start");
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(screen.getByText("or sign in with a password")).toBeInTheDocument();
  });

  it("shows only single sign-on when password sign-in is off", () => {
    sso = "Sign in with SSO";
    localLogin = false;
    render(<Login />);
    expect(screen.getByRole("link", { name: "Sign in with SSO" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
    expect(screen.queryByText("or sign in with a password")).not.toBeInTheDocument();
  });

  it("explains a failed single sign-on, and forgets it on reload", () => {
    sso = "Sign in with SSO";
    window.history.replaceState(null, "", "/?sso_error=unauthorized");
    render(<Login />);
    expect(screen.getByRole("alert")).toHaveTextContent(/not in a group that may use Retune/);
    expect(window.location.search).toBe("");
  });

  it("says something sensible about a code it does not know", () => {
    window.history.replaceState(null, "", "/?sso_error=something_new");
    render(<Login />);
    expect(screen.getByRole("alert")).toHaveTextContent(/Single sign-on failed/);
  });
});
