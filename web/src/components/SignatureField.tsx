import { Field } from "./ui";

export interface OperationSignature {
  key_id: string;
  signature: string;
}

/** SignedOrder is what `retune-sign sign-wipe` prints. */
export interface SignedOrder extends OperationSignature {
  device?: string;
  protected?: boolean;
  expires: string;
}

/**
 * parseSignature reads the JSON retune-sign prints, or null when the text
 * isn't one: pasted wholesale, so nobody has to copy fields across by hand.
 */
export function parseSignature(text: string): OperationSignature | null {
  try {
    const value = JSON.parse(text) as Partial<SignedOrder>;
    if (typeof value.key_id === "string" && typeof value.signature === "string" && value.signature) {
      return { key_id: value.key_id, signature: value.signature };
    }
  } catch {
    // not JSON
  }
  return null;
}

/** parseSignedOrder reads a signed wipe order, or null. */
export function parseSignedOrder(text: string): SignedOrder | null {
  const sig = parseSignature(text);
  if (!sig) return null;
  const value = JSON.parse(text) as Partial<SignedOrder>;
  if (typeof value.expires !== "string" || Number.isNaN(Date.parse(value.expires))) return null;
  return { ...sig, device: value.device, protected: value.protected, expires: value.expires };
}

/** SignatureField takes a pasted operations signature, and says how to make one. */
export function SignatureField({
  value,
  onChange,
  command,
  label = "Operations signature",
  valid,
}: {
  value: string;
  onChange: (value: string) => void;
  /** command is the retune-sign line that produces what goes here. */
  command: string;
  label?: string;
  valid: boolean;
}) {
  return (
    <Field
      label={label}
      hint={`Your agents only run what an operations key has signed. On the machine that holds the key, run: ${command} — and paste what it prints.`}
      error={value.trim() !== "" && !valid ? "That isn't what retune-sign prints." : undefined}
    >
      <textarea
        aria-label={label}
        className="mono"
        rows={3}
        spellCheck={false}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </Field>
  );
}
