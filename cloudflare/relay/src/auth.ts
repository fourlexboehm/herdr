import {
  ROUTE_BYTES,
  ROUTE_LENGTH,
  ROUTE_PATTERN,
} from "./config";
import { decodeBase64Url, encodeBase64Url } from "./base64";

const BEARER_PREFIX = "Bearer ";
const REGISTRATION_SALT_BYTES = 32;

export interface RegistrationVerifier {
  salt: string;
  verifier: string;
}

export function isValidRoute(value: string | null): value is string {
  return (
    value !== null &&
    value.length === ROUTE_LENGTH &&
    ROUTE_PATTERN.test(value)
  );
}

export function parseTargetCapability(
  authorization: string | null,
): string | null {
  if (
    authorization === null ||
    !authorization.startsWith(BEARER_PREFIX)
  ) {
    return null;
  }

  const capability = authorization.slice(BEARER_PREFIX.length);
  if (
    capability.length !== ROUTE_LENGTH ||
    !ROUTE_PATTERN.test(capability)
  ) {
    return null;
  }

  return capability;
}

export async function createRegistrationVerifier(
  route: string,
  capability: string,
): Promise<RegistrationVerifier | null> {
  const saltBytes = crypto.getRandomValues(
    new Uint8Array(REGISTRATION_SALT_BYTES),
  );
  const verifierBytes = await hashRegistrationCapability(
    route,
    capability,
    saltBytes,
  );
  if (verifierBytes === null) {
    return null;
  }

  return {
    salt: encodeBase64Url(saltBytes),
    verifier: encodeBase64Url(verifierBytes),
  };
}

export async function verifyRegistrationCapability(
  route: string,
  capability: string,
  registration: RegistrationVerifier,
): Promise<boolean | null> {
  const saltBytes = decodeBase64Url(
    registration.salt,
    REGISTRATION_SALT_BYTES,
  );
  const expectedVerifier = decodeBase64Url(
    registration.verifier,
    ROUTE_BYTES,
  );
  if (saltBytes === null || expectedVerifier === null) {
    return null;
  }

  const actualVerifier = await hashRegistrationCapability(
    route,
    capability,
    saltBytes,
  );
  return actualVerifier === null
    ? false
    : crypto.subtle.timingSafeEqual(actualVerifier, expectedVerifier);
}

async function hashRegistrationCapability(
  route: string,
  capability: string,
  salt: Uint8Array,
): Promise<Uint8Array | null> {
  const routeBytes = decodeBase64Url(route, ROUTE_BYTES);
  const capabilityBytes = decodeBase64Url(capability, ROUTE_BYTES);
  if (routeBytes === null || capabilityBytes === null) {
    return null;
  }

  const input = new Uint8Array(
    salt.byteLength + routeBytes.byteLength + capabilityBytes.byteLength,
  );
  input.set(salt, 0);
  input.set(routeBytes, salt.byteLength);
  input.set(capabilityBytes, salt.byteLength + routeBytes.byteLength);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", input));
}
