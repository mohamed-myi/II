import FingerprintJS from "@fingerprintjs/fingerprintjs";

let cachedFingerprint: string | null = null;

/**
 * Generates a stable browser fingerprint using FingerprintJS;
 * result is cached for the session lifetime to avoid redundant computation
 */
export async function getFingerprint(): Promise<string> {
    if (cachedFingerprint) {
        return cachedFingerprint;
    }

    const fp = await FingerprintJS.load();
    const result = await fp.get();
    cachedFingerprint = result.visitorId;
    return result.visitorId;
}

/**
 * Returns cached fingerprint without async computation;
 * returns null if fingerprint has not been generated yet
 */
export function getCachedFingerprint(): string | null {
    return cachedFingerprint;
}

/**
 * Clears cached fingerprint; useful for testing or forced regeneration
 */
export function clearFingerprintCache(): void {
    cachedFingerprint = null;
}
