<script lang="ts">
  // Small stroke icons (24px grid). Shape icons mirror how the diagram draws each element.
  let { name, size = 16 }: { name: string; size?: number } = $props();
  const paths: Record<string, string> = {
    actor: '<rect x="3" y="6" width="18" height="12" rx="1"/>',
    process: '<circle cx="12" cy="12" r="8"/>',
    store: '<path d="M3 7h18M3 17h18"/>',
    flow: '<path d="M4 17C9 17 11 7 16 7h3"/><path d="m16 4 3 3-3 3"/>',
    boundary_box: '<rect x="3" y="4" width="18" height="16" rx="3" stroke-dasharray="3 2.5"/>',
    boundary_curve: '<path d="M3 18C8 18 9 6 21 6" stroke-dasharray="3 2.5"/>',
    text: '<path d="M5 6h14M12 6v12M9 18h6"/>',
    new: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M12 11v6M9 14h6"/>',
    open: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    save: '<path d="M5 3h11l5 5v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M7 3v5h8M7 21v-7h10v7"/>',
    export: '<path d="M12 3v12M7 8l5-5 5 5"/><path d="M5 14v5a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-5"/>',
    report: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>',
    undo: '<path d="M9 14 4 9l5-5"/><path d="M4 9h11a5 5 0 0 1 0 10h-3"/>',
    redo: '<path d="m15 14 5-5-5-5"/><path d="M20 9H9a5 5 0 0 0 0 10h3"/>',
    zoomin: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5M11 8v6M8 11h6"/>',
    zoomout: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5M8 11h6"/>',
    design: '<path d="M4 20l4-1 11-11-3-3L5 16z"/><path d="M14 7l3 3"/>',
    analysis: '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/><path d="M9 12l2 2 4-4"/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="1"/><path d="M5 15V5a1 1 0 0 1 1-1h9"/>',
    cut: '<circle cx="6" cy="18" r="3"/><circle cx="18" cy="18" r="3"/><path d="M8.5 16 19 4M15.5 16 5 4"/>',
    paste: '<rect x="5" y="4" width="14" height="17" rx="1"/><path d="M9 4V2.5h6V4M9 10h6M9 14h6"/>',
    diagramadd: '<rect x="3" y="5" width="14" height="14" rx="1"/><path d="M20 3v6M17 6h6"/>',
    diagramdel: '<rect x="3" y="5" width="14" height="14" rx="1"/><path d="M17 6h6"/>',
    note: '<path d="M5 4h14v11l-5 5H5z"/><path d="M14 20v-5h5M8 9h8M8 13h5"/>',
    fit: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>',
    trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    close: '<path d="M6 6l12 12M18 6 6 18"/>',
    chevron: '<path d="m6 9 6 6 6-6"/>',
    lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    target: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>',
    warning: '<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17v.5"/>',
    shield: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/>',
    panel: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 14h18"/>',
  };
</script>

<svg
  class="icon"
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="1.8"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true">{@html paths[name] ?? ""}</svg
>

<style>
  .icon { flex: none; display: block; }
</style>
