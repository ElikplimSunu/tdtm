// Threat Dragon v2 JSON is open-ended; these types name only what the app reads.
export type Cell = { id: string; shape: string; data?: any; [k: string]: any };
export type Diagram = { id: number | string; title: string; diagramType?: string; cells: Cell[]; [k: string]: any };
export type Model = {
  version?: string;
  summary: { title: string; owner?: string; description?: string; [k: string]: any };
  detail: { diagrams: Diagram[]; [k: string]: any };
  [k: string]: any;
};

export type ThreatRow = {
  key: string; id: number | null; cell: string; diagram: string; interaction: string;
  source: string; target: string; state: string; title: string; category: string;
  description: string; justification: string; priority: string; generatedBy: string; editable: boolean;
};

export type Attribute = { name: string; label: string; value: string; values: string[]; source: string; static: boolean };
export type ElementInfo = { kind: string; stencil: string; stencilName: string; zone: string | null; crosses: string[]; attributes: Attribute[] };

export type AnalyzeResult = {
  model: Model; threats: ThreatRow[]; elements: Record<string, ElementInfo>; warnings: string[]; review: string[];
  counts: { added: number; refreshed: number; unchanged: number; edited: number; stale: number };
};

export type Stencil = { id: string; name: string; generic: boolean; icon: string; iconAt: "center" | "lower-right" | "before-label" };
export type Palette = Record<"actor" | "process" | "store" | "flow" | "boundary_box" | "boundary_curve", Stencil[]>;

export const STATES = ["Not Started", "Needs Investigation", "Not Applicable", "Mitigated"] as const;
export const PRIORITIES = ["High", "Medium", "Low", "Critical", "TBD"] as const;
