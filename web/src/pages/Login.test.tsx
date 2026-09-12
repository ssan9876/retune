import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../api/client";
import Login from "./Login";

const signIn = vi.fn();
let needsSetup = false;

vi.mock("../session/SessionContext", () => ({
  useSession: () => ({
    admin: null,
    loading: false,
    needsSetup,
    canWrite: false,
    signIn,
    signOut: vi.fn(),
  }),
}));

beforeEach(() => {
  signIn.mockReset();
  needsSetup = false;
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
});
