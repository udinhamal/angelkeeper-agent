/**
 * Minimal ambient declaration for snarkjs (no official typings).
 * Only the surface this project uses is described, loosely.
 *
 * Adapted from the standalone agent: wasm/zkey arguments may be file paths
 * OR in-memory buffers (Uint8Array). The serverless proof module passes
 * buffers loaded with fs.readFileSync so the function does not depend on
 * runtime file paths for the circuit artifacts.
 */
declare module "snarkjs" {
  export const groth16: {
    fullProve(
      input: Record<string, string>,
      wasmFile: string | Uint8Array,
      zkeyFile: string | Uint8Array,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    verify(
      verificationKey: unknown,
      publicSignals: string[],
      proof: unknown,
    ): Promise<boolean>;
  };
  export const zKey: {
    exportVerificationKey(zkeyFile: string | Uint8Array): Promise<unknown>;
  };
}
