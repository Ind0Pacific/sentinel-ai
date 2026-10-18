"use client";

import React, { useEffect, useState } from "react";
import { Database, RefreshCw, FileText, CheckCircle, AlertTriangle } from "lucide-react";

export default function DatasetExplorer() {
  const [datasets, setDatasets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedDataset, setSelectedDataset] = useState<any>(null);

  const fetchDatasets = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/datasets");
      if (res.ok) {
        const data = await res.json();
        setDatasets(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const inspectDataset = async (id: string) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/v1/datasets/${id}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedDataset(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchDatasets();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Dataset Explorer</h2>
          <p className="text-sm text-slate-400">Inspected public benchmarks, licensing, and schema verification.</p>
        </div>
        <button
          onClick={fetchDatasets}
          className="text-xs text-teal-400 hover:underline flex items-center space-x-1 font-mono"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>

      {loading ? (
        <div className="p-12 text-center text-slate-500 font-mono">Loading manifests from API...</div>
      ) : datasets.length === 0 ? (
        <div className="p-8 text-center text-slate-500 bg-slate-900 border border-slate-800 rounded-xl">
          No dataset manifests registered. Please run the pipeline first.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {datasets.map((d) => (
            <div
              key={d.id}
              onClick={() => inspectDataset(d.id)}
              className="bg-slate-900/80 border border-slate-800 hover:border-teal-500/50 rounded-xl p-5 space-y-3 cursor-pointer transition"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-teal-300 font-semibold">
                  {d.id}
                </span>
                <span className="text-xs text-slate-400 font-mono">{d.license}</span>
              </div>
              <h3 className="text-base font-bold text-white">{d.dataset_name}</h3>
              <p className="text-xs text-slate-400 truncate" title={d.source_url}>
                {d.source_url}
              </p>
              <div className="border-t border-slate-800 pt-3 flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">Records:</span>
                <span className="text-white font-bold">
                  {typeof d.record_counts === "object" ? JSON.stringify(d.record_counts) : d.record_counts}
                </span>
              </div>
              <div className="text-[10px] text-slate-500 font-mono truncate">
                SHA: {d.sha256_checksum.substring(0, 16)}...
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Detail Modal / Drawer */}
      {selectedDataset && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-6 z-50">
          <div className="bg-[#0d1527] border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-lg font-bold text-white">{selectedDataset.dataset_name}</h3>
              <button
                onClick={() => setSelectedDataset(null)}
                className="text-slate-400 hover:text-white text-sm font-mono"
              >
                ✕ Close
              </button>
            </div>
            <div className="space-y-3 text-xs font-mono">
              <p><b className="text-slate-400">Source:</b> {selectedDataset.source_url}</p>
              <p><b className="text-slate-400">License:</b> {selectedDataset.license}</p>
              <p><b className="text-slate-400">Original File:</b> {selectedDataset.original_filename}</p>
              <p><b className="text-slate-400">File Size:</b> {selectedDataset.file_size_bytes} bytes</p>
              <p><b className="text-slate-400">SHA-256:</b> <span className="text-teal-300">{selectedDataset.sha256_checksum}</span></p>
              <div>
                <b className="text-slate-400 block mb-1">Known Limitations:</b>
                <ul className="list-disc list-inside space-y-0.5 text-slate-300">
                  {selectedDataset.known_limitations?.map((lim: string, idx: number) => (
                    <li key={idx}>{lim}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
