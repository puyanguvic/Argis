let mermaidModulePromise: Promise<typeof import("mermaid")> | null = null;

async function getMermaid() {
  const mermaidModule = await (mermaidModulePromise ??= import("mermaid"));
  return mermaidModule.default;
}

export async function init(externalDiagrams: unknown[] = []) {
  const mermaid = await getMermaid();
  if (!externalDiagrams.length || typeof mermaid.registerExternalDiagrams !== "function") {
    return;
  }

  try {
    await mermaid.registerExternalDiagrams(externalDiagrams as never[]);
  } catch (error) {
    console.error(error);
  }
}

export async function render(
  id: string,
  code: string,
  config: Record<string, unknown>
): Promise<string> {
  const mermaid = await getMermaid();
  mermaid.initialize(config as never);
  const { svg } = await mermaid.render(id, code);
  return svg;
}
