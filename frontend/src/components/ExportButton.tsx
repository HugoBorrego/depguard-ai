/** Botão de exportação do relatório em JSON. */

import { buildExportPayload, downloadText, exportFilename } from "@/lib/format";
import type { AnalysisReport, DependencyFinding } from "@/types/api";
import { Icon } from "./Icon";

export function ExportButton({
  report,
  findings,
  onExport,
}: {
  report: AnalysisReport;
  findings: readonly DependencyFinding[];
  onExport: () => void;
}) {
  function handleClick(): void {
    downloadText(
      exportFilename(report.project.name),
      buildExportPayload(report, findings),
    );
    onExport();
  }

  return (
    <button
      type="button"
      className="btn-secondary"
      onClick={handleClick}
      title="Baixar o relatório completo em JSON"
    >
      <Icon name="file" />
      Exportar JSON
    </button>
  );
}
