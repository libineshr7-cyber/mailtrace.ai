// ============================================================
// MAILTRACE AI — Investigation Graph Tab (React Flow)
// Forensic indicator relationship & infrastructure graph
// ============================================================
import { useState, useEffect } from 'react';
import ReactFlow, {
  Background, Controls, MiniMap,
  type Node, type Edge, BackgroundVariant,
  useNodesState, useEdgesState, MarkerType
} from 'reactflow';
import 'reactflow/dist/style.css';
import {
  GitFork, Shield, Globe, Server, Mail, Link2,
  FileText, Hash, X, Info, Filter, ArrowRight
} from 'lucide-react';
import { getGraph } from '../../services/api';
import type { InvestigationGraph, GraphNode, GraphNodeType } from '../../types';
import { RiskBadge, VerdictBadge } from '../ui/Badge';
import { LoadingOverlay, ErrorState } from '../ui/States';

interface Props {
  investigationId: string;
}

const NODE_COLORS: Record<GraphNodeType, { border: string; bg: string; text: string }> = {
  EMAIL:       { border: '#388bfd', bg: '#0d2040', text: '#58a6ff' },
  SENDER:      { border: '#d29922', bg: '#2f2108', text: '#e3b341' },
  REPLY_TO:    { border: '#d29922', bg: '#2f2108', text: '#e3b341' },
  DOMAIN:      { border: '#8b949e', bg: '#21262d', text: '#c9d1d9' },
  URL:         { border: '#f85149', bg: '#3d1a19', text: '#ff7b72' },
  IP:          { border: '#f85149', bg: '#3d1a19', text: '#ff7b72' },
  ASN:         { border: '#6e7681', bg: '#161b22', text: '#8b949e' },
  ATTACHMENT:  { border: '#d29922', bg: '#2f2108', text: '#e3b341' },
  HASH:        { border: '#8b949e', bg: '#21262d', text: '#8b949e' },
};

function calculateHierarchicalLayout(rawNodes: GraphNode[]): Record<string, { x: number; y: number }> {
  const typeOrder: Record<string, number> = {
    EMAIL: 0,
    SENDER: 1,
    REPLY_TO: 1,
    DOMAIN: 2,
    IP: 3,
    ASN: 3,
    URL: 4,
    ATTACHMENT: 4,
    HASH: 5,
  };

  const rows: Record<number, GraphNode[]> = {};
  rawNodes.forEach((n) => {
    const lvl = typeOrder[n.type] ?? 3;
    if (!rows[lvl]) rows[lvl] = [];
    rows[lvl].push(n);
  });

  const positions: Record<string, { x: number; y: number }> = {};
  const rowSpacingY = 120;
  const colSpacingX = 220;

  Object.entries(rows).forEach(([lvlStr, nodesInRow]) => {
    const lvl = parseInt(lvlStr, 10);
    const y = 50 + lvl * rowSpacingY;
    const count = nodesInRow.length;
    const startX = 400 - ((count - 1) * colSpacingX) / 2;

    nodesInRow.forEach((n, idx) => {
      positions[n.id] = {
        x: startX + idx * colSpacingX,
        y,
      };
    });
  });

  return positions;
}

export default function GraphTab({ investigationId }: Props) {
  const [graphData, setGraphData] = useState<InvestigationGraph | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  const loadGraph = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await getGraph(investigationId);
      setGraphData(res);

      const positions = calculateHierarchicalLayout(res.nodes);

      // Build React Flow nodes
      const rfNodes: Node[] = res.nodes.map((n) => {
        const colors = NODE_COLORS[n.type] || { border: '#30363d', bg: '#161b22', text: '#e6edf3' };
        const pos = positions[n.id] || { x: 300, y: 300 };

        return {
          id: n.id,
          type: 'default',
          position: pos,
          data: { label: `${n.type}: ${n.label}`, rawNode: n },
          style: {
            background: colors.bg,
            border: `1px solid ${colors.border}`,
            borderRadius: '4px',
            color: colors.text,
            fontFamily: 'IBM Plex Mono, monospace',
            fontSize: '11px',
            padding: '6px 10px',
            width: 170,
            cursor: 'pointer',
            boxShadow: '0 2px 8px rgba(0,0,0,0.5)',
          },
        };
      });

      // Build React Flow edges
      const rfEdges: Edge[] = res.edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label,
        markerEnd: { type: MarkerType.ArrowClosed, color: '#6e7681', width: 14, height: 14 },
        style: { stroke: '#484f58', strokeWidth: 1.5 },
        labelStyle: { fill: '#8b949e', fontSize: 9, fontFamily: 'monospace' },
        labelBgStyle: { fill: '#161b22', fillOpacity: 0.85 },
      }));

      setNodes(rfNodes);
      setEdges(rfEdges);
      if (res.nodes.length > 0) setSelectedNode(res.nodes[0]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load graph');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadGraph();
  }, [investigationId]);

  if (loading) return <LoadingOverlay message="Generating investigation correlation graph..." />;
  if (error) return <ErrorState message={error} retry={loadGraph} />;

  const onNodeClick = (_: React.MouseEvent, node: Node) => {
    if (node.data?.rawNode) {
      setSelectedNode(node.data.rawNode);
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Legend Bar */}
      <div className="panel p-3 flex items-center justify-between flex-wrap gap-2 text-xs">
        <div className="flex items-center gap-4 flex-wrap">
          <span className="font-semibold text-text-primary text-2xs uppercase tracking-wider">Node Types:</span>
          {Object.entries(NODE_COLORS).map(([type, c]) => (
            <div key={type} className="flex items-center gap-1.5 text-2xs">
              <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: c.border }} />
              <span className="text-text-secondary font-mono">{type}</span>
            </div>
          ))}
        </div>
        <div className="text-2xs text-text-muted">
          Click any node to inspect relationship telemetry
        </div>
      </div>

      {/* Graph Area */}
      <div className="panel relative h-[420px] sm:h-[560px] overflow-hidden">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          attributionPosition="bottom-left"
        >
          <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="#30363d" />
          <Controls className="react-flow-dark-controls" />
          <MiniMap
            nodeColor={(n) => {
              const type = n.data?.rawNode?.type as GraphNodeType;
              return NODE_COLORS[type]?.border || '#30363d';
            }}
            maskColor="rgba(13, 17, 23, 0.7)"
            style={{ backgroundColor: '#161b22', border: '1px solid #30363d', borderRadius: 4 }}
          />
        </ReactFlow>

        {/* Node Detail Drawer / Floating Inspector */}
        {selectedNode && (
          <div className="absolute top-2 right-2 left-2 sm:left-auto sm:right-3 sm:top-3 sm:w-80 max-h-[85%] overflow-y-auto bg-bg-secondary border border-border rounded shadow-drawer p-3 sm:p-4 text-xs z-10 space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center gap-2">
                <GitFork className="w-4 h-4 text-accent-blue" />
                <span className="font-semibold text-text-primary">Node Inspector</span>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="p-1 text-text-muted hover:text-text-primary"
              >
                <X size={14} />
              </button>
            </div>

            <div>
              <div className="text-2xs text-text-muted uppercase">Entity Classification</div>
              <div className="flex items-center gap-2 mt-1">
                <span className="badge bg-bg-tertiary border border-border text-text-primary font-mono text-2xs">
                  {selectedNode.type}
                </span>
                {selectedNode.riskLevel && <RiskBadge level={selectedNode.riskLevel} />}
                {selectedNode.verdict && <VerdictBadge verdict={selectedNode.verdict} />}
              </div>
            </div>

            <div>
              <div className="text-2xs text-text-muted uppercase">Entity Value</div>
              <div className="p-2 bg-bg-primary border border-border rounded font-mono text-2xs text-text-primary break-all mt-1">
                {selectedNode.label}
              </div>
            </div>

            {selectedNode.data && Object.keys(selectedNode.data).length > 0 && (
              <div className="space-y-1.5 pt-2 border-t border-border">
                <div className="text-2xs text-text-muted uppercase">Forensic Metadata</div>
                <div className="bg-bg-tertiary p-2 rounded border border-border space-y-1 font-mono text-2xs">
                  {Object.entries(selectedNode.data).map(([k, v]) => (
                    <div key={k} className="flex justify-between">
                      <span className="text-text-muted">{k}:</span>
                      <span className="text-text-secondary truncate max-w-[140px]">{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="pt-2 border-t border-border text-2xs text-text-muted">
              Relationship Links: <span className="text-text-secondary font-mono">
                {edges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id).length} edges
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
