#!/usr/bin/env bash
# Puts the release signing key into a release job's environment, for
# retune-sign --key env:RELEASE_KEY and deploy/msi/build.ps1.
#
# A release (RELEASE=true) takes the RELEASE_KEY secret and fails without it:
# an unsigned agent is never published. A dry run takes the throwaway key the
# prepare job made, from $RUNNER_TEMP/dryrun-key/release.key.
#
# Exports RELEASE_KEY, RELEASE_PUB (its public key) and TRUSTED_KEYS (what the
# agent embeds: RELEASE_PUBKEYS when set, for a key rotation, else RELEASE_PUB).
set -euo pipefail

if [ "${RELEASE:-false}" = true ]; then
  if [ -z "${RELEASE_KEY:-}" ]; then
    echo "::error::The RELEASE_KEY secret is not set. Refusing to publish unsigned agents."
    exit 1
  fi
  key=$RELEASE_KEY
else
  key=$(cat "$RUNNER_TEMP/dryrun-key/release.key")
  RELEASE_PUBKEYS=""
fi
key=$(printf '%s' "$key" | tr -d '\r\n ')
echo "::add-mask::$key"

pub=$(RELEASE_KEY="$key" go run ./cmd/retune-sign pubkey --key env:RELEASE_KEY)
trust=${RELEASE_PUBKEYS:-$pub}
trust=$(printf '%s' "$trust" | tr -d '\r\n ')
case ",$trust," in
  *",$pub,"*) ;;
  *)
    echo "::error::RELEASE_PUBKEYS does not include the public key of RELEASE_KEY ($pub); agents would not trust their own build."
    exit 1
    ;;
esac

{
  echo "RELEASE_KEY=$key"
  echo "RELEASE_PUB=$pub"
  echo "TRUSTED_KEYS=$trust"
} >> "$GITHUB_ENV"
echo "release key $pub; agents trust: $trust"
