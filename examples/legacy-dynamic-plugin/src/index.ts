export function loadTenantFormatter(moduleName: string): unknown {
  // Dynamic require obscures static call graph — VEXProof MUST flag under_investigation
  return require(moduleName);
}
