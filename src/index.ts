/**
 * @latticeag/ghostsession — public API surface.
 */

export { RpcError, type ErrorCode } from "./errors.js";
export { Client, UnixSocketTransport, RemoteTransport, RpcFailure } from "./client.js";
export { newId, isValidId } from "./ids.js";
export { jcsBytes, jcsString } from "./encoding/jcs.js";
export { parseStrictJson } from "./encoding/strict-json.js";
export { classify, probeVerified } from "./classify.js";
export { computeDelay } from "./delay.js";
export type * from "./schema.js";
