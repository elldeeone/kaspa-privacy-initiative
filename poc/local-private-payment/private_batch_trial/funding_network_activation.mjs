// Source-only profile boundary. Serialized files, argv and environment values
// cannot turn this into a capability. A future parent-owned implementation must
// replace this with a live one-shot authority that is never exported or saved.
export const NETWORK_ACTIVATION_CONFIGURED = false;

export function requireLiveNetworkActivation() {
  if (!NETWORK_ACTIVATION_CONFIGURED)
    throw new Error('PARENT_LIVE_NETWORK_ACTIVATION_NOT_CONFIGURED');
}
