import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Cpu,
  Network,
  Radio,
  CheckCircle2,
  ArrowRight,
  Search,
  Filter,
  Activity,
  Layers,
  RefreshCw,
  X,
  ChevronRight,
  Plus,
  Trash2,
  Play,
  GitCompare,
  RotateCcw,
  Edit3,
  Sliders,
  Terminal,
} from 'lucide-react';
import initialVehicleData from './vehicle_v1.json';

const DEFAULT_API_URL = 'http://127.0.0.1:8001';
const API_BASE_URL =
  import.meta.env.VITE_API_URL !== undefined && import.meta.env.VITE_API_URL !== ''
    ? import.meta.env.VITE_API_URL
    : DEFAULT_API_URL;

// Dynamically extract the configured API port for UI indicators
const getTargetApiPort = () => {
  try {
    const url = new URL(API_BASE_URL, window.location.href);
    return url.port || (url.protocol === 'https:' ? '443' : '80');
  } catch {
    return '8001';
  }
};
const CONFIGURED_API_PORT = getTargetApiPort();

export default function App() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null);
  const [healthStatus, setHealthStatus] = useState('checking');

  // Baseline Architecture (V1) - Immutable baseline
  const [v1Baseline, setV1Baseline] = useState(initialVehicleData);

  // Target Architecture (V2) - Working version
  const [v2Architecture, setV2Architecture] = useState(initialVehicleData);
  const v2ArchitectureRef = useRef(v2Architecture);

  // Architecture Comparison Result from backend
  const [diffResult, setDiffResult] = useState(null);
  const [isComparing, setIsComparing] = useState(false);
  const [comparisonError, setComparisonError] = useState(null);

  // Filtering states for threats
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [strideFilter, setStrideFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Selected threat for detail modal
  const [selectedThreat, setSelectedThreat] = useState(null);

  // Active section tab for navigation
  const [activeTab, setActiveTab] = useState('all');

  // Architecture Editor Modal state
  const [isEditorOpen, setIsEditorOpen] = useState(false);
  const [newIfaceSource, setNewIfaceSource] = useState('infotainment');
  const [newIfaceTarget, setNewIfaceTarget] = useState('external');
  const [newIfaceProtocol, setNewIfaceProtocol] = useState('Wi-Fi');

  const [newCompId, setNewCompId] = useState('');
  const [newCompName, setNewCompName] = useState('');
  const [newCompType, setNewCompType] = useState('ECU');
  const [editorValidationMsg, setEditorValidationMsg] = useState(null);

  // Test execution state & logs
  const [executingTestId, setExecutingTestId] = useState(null);
  const [isExecutingAllTests, setIsExecutingAllTests] = useState(false);
  const [executedTestResults, setExecutedTestResults] = useState({});
  const [expandedLogTestId, setExpandedLogTestId] = useState(null);
  const [testExecutionError, setTestExecutionError] = useState(null);

  // Helper: call API with fallback to direct localhost:8001
  const fetchWithFallback = async (endpoint, options = {}) => {
    try {
      const res = await fetch(`${API_BASE_URL}${endpoint}`, options);
      return res;
    } catch (err) {
      if (API_BASE_URL !== DEFAULT_API_URL) {
        return await fetch(`${DEFAULT_API_URL}${endpoint}`, options);
      }
      throw err;
    }
  };

  // Run Baseline Analysis
  const runBaselineAnalysis = async () => {
    setLoading(true);
    setError(null);
    setHealthStatus('checking');
    try {
      // 1. Health check
      try {
        const healthRes = await fetchWithFallback('/api/health');
        if (healthRes.ok) {
          setHealthStatus('connected');
        } else {
          setHealthStatus('degraded');
        }
      } catch (hErr) {
        setHealthStatus('offline');
      }

      // 2. Fetch baseline from backend if available
      try {
        const baselineRes = await fetchWithFallback('/api/baseline');
        if (baselineRes.ok) {
          const bData = await baselineRes.json();
          setV1Baseline(bData);
        }
      } catch (bErr) {
        // Fall back to initialVehicleData
      }

      // 3. Analyze Baseline
      const response = await fetchWithFallback('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(v1Baseline),
      });

      if (!response.ok) {
        const errJson = await response.json().catch(() => null);
        throw new Error(errJson?.detail || `API error: ${response.status}`);
      }

      const result = await response.json();
      setData(result);
      setHealthStatus('connected');

      // Also trigger initial comparison with V2
      runArchitectureComparison(v1Baseline, v2Architecture);
    } catch (err) {
      console.error('Failed to run analysis:', err);
      setError(err.message || 'Failed to connect to ThreatLens-AI backend');
      setHealthStatus('offline');
    } finally {
      setLoading(false);
    }
  };

  // Run Architecture Comparison & Revalidation Analysis
  const runArchitectureComparison = async (baseline = v1Baseline, target = v2Architecture) => {
    setIsComparing(true);
    setComparisonError(null);
    try {
      const res = await fetchWithFallback('/api/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          baseline: baseline,
          target: target,
        }),
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => null);
        throw new Error(errJson?.detail || `Comparison failed: HTTP ${res.status}`);
      }

      const comparison = await res.json();
      setDiffResult(comparison);
    } catch (err) {
      console.error('Comparison error:', err);
      setComparisonError(err.message || 'Failed to compare architecture versions');
    } finally {
      setIsComparing(false);
    }
  };

  useEffect(() => {
    runBaselineAnalysis();
  }, []);

  // Update comparison whenever V2 architecture changes
  const applyV2Change = (newV2) => {
    v2ArchitectureRef.current = newV2;
    setV2Architecture(newV2);
    setTestExecutionError(null);
    setExecutedTestResults({});
    runArchitectureComparison(v1Baseline, newV2);
  };

  // Quick Preset Actions
  const handlePresetAddWifi = () => {
    const updated = JSON.parse(JSON.stringify(v1Baseline));
    updated.system = 'Connected Vehicle V2 (Wi-Fi Enabled)';
    // Check if wifi already exists
    const hasWifi = updated.interfaces.some(
      (i) => i.source === 'infotainment' && i.target === 'external' && i.protocol === 'Wi-Fi'
    );
    if (!hasWifi) {
      updated.interfaces.push({
        source: 'infotainment',
        target: 'external',
        protocol: 'Wi-Fi',
      });
    }
    applyV2Change(updated);
  };

  const handlePresetAddDiagnostic = () => {
    const updated = JSON.parse(JSON.stringify(v2Architecture));
    updated.system = 'Connected Vehicle V2 (OBD-II Service Port)';
    const hasDiag = updated.interfaces.some(
      (i) => i.source === 'gateway' && i.target === 'external' && i.protocol === 'Diagnostic'
    );
    if (!hasDiag) {
      updated.interfaces.push({
        source: 'gateway',
        target: 'external',
        protocol: 'Diagnostic',
      });
    }
    applyV2Change(updated);
  };

  const handlePresetResetBaseline = () => {
    const resetV2 = JSON.parse(JSON.stringify(v1Baseline));
    applyV2Change(resetV2);
    setExecutedTestResults({});
  };

  // Interface addition in editor
  const handleAddInterface = () => {
    if (!newIfaceSource || !newIfaceTarget || !newIfaceProtocol) {
      setEditorValidationMsg('Source, target, and protocol are all required.');
      return;
    }
    if (newIfaceSource === newIfaceTarget) {
      setEditorValidationMsg('Source and target must be distinct nodes.');
      return;
    }

    const updated = JSON.parse(JSON.stringify(v2Architecture));
    const exists = updated.interfaces.some(
      (i) =>
        i.source === newIfaceSource &&
        i.target === newIfaceTarget &&
        i.protocol === newIfaceProtocol
    );
    if (exists) {
      setEditorValidationMsg('This interface already exists in V2 topology.');
      return;
    }

    updated.interfaces.push({
      source: newIfaceSource,
      target: newIfaceTarget,
      protocol: newIfaceProtocol,
    });
    setEditorValidationMsg(null);
    applyV2Change(updated);
  };

  // Remove interface
  const handleRemoveInterface = (index) => {
    const updated = JSON.parse(JSON.stringify(v2Architecture));
    updated.interfaces.splice(index, 1);
    applyV2Change(updated);
  };

  // Add Component in editor
  const handleAddComponent = () => {
    if (!newCompId.trim() || !newCompName.trim()) {
      setEditorValidationMsg('Component ID and Name are required.');
      return;
    }
    const cleanId = newCompId.trim().toLowerCase().replace(/\s+/g, '_');
    const updated = JSON.parse(JSON.stringify(v2Architecture));
    const exists = updated.components.some((c) => c.id === cleanId);
    if (exists) {
      setEditorValidationMsg(`Component with ID '${cleanId}' already exists.`);
      return;
    }

    updated.components.push({
      id: cleanId,
      name: newCompName.trim(),
      type: newCompType,
    });
    setNewCompId('');
    setNewCompName('');
    setEditorValidationMsg(null);
    applyV2Change(updated);
  };

  // Remove Component
  const handleRemoveComponent = (compId) => {
    const updated = JSON.parse(JSON.stringify(v2Architecture));
    updated.components = updated.components.filter((c) => c.id !== compId);
    // Remove linked interfaces
    updated.interfaces = updated.interfaces.filter(
      (i) => i.source !== compId && i.target !== compId
    );
    applyV2Change(updated);
  };

  // Execute Security Validation Tests against Target Architecture
  const handleExecuteTests = async (testIdsToRun = null) => {
    const architecture = v2ArchitectureRef.current;
    setTestExecutionError(null);
    if (testIdsToRun) {
      setExecutingTestId(testIdsToRun[0]);
    } else {
      setIsExecutingAllTests(true);
    }

    try {
      const res = await fetchWithFallback('/api/execute-tests', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          test_ids: testIdsToRun,
          architecture,
        }),
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => null);
        throw new Error(errJson?.detail || 'Test execution failed');
      }

      const resData = await res.json();
      setExecutedTestResults((prev) => {
        if (v2ArchitectureRef.current !== architecture) return prev;
        const updatedMap = { ...prev };
        resData.executed_tests.forEach((t) => {
          updatedMap[t.id] = t;
        });
        return updatedMap;
      });
    } catch (err) {
      console.error('Test execution error:', err);
      setTestExecutionError(err.message || 'Test execution failed');
    } finally {
      setExecutingTestId(null);
      setIsExecutingAllTests(false);
    }
  };

  // Filtered threats / findings (for Threat Analysis section)
  const filteredFindings = useMemo(() => {
    const sourceList = diffResult?.v2_analysis?.security_findings || data?.security_findings;
    if (!sourceList) return [];

    return sourceList.filter((finding) => {
      if (riskFilter !== 'ALL' && finding.risk_level.toUpperCase() !== riskFilter) {
        return false;
      }
      if (strideFilter !== 'ALL' && finding.stride_category !== strideFilter) {
        return false;
      }
      if (searchQuery.trim() !== '') {
        const query = searchQuery.toLowerCase();
        return (
          (finding.threat_id || '').toLowerCase().includes(query) ||
          (finding.stride_category || '').toLowerCase().includes(query) ||
          (finding.protocol || '').toLowerCase().includes(query) ||
          (finding.source || '').toLowerCase().includes(query) ||
          (finding.target || '').toLowerCase().includes(query) ||
          (finding.cwe || '').toLowerCase().includes(query) ||
          (finding.description || '').toLowerCase().includes(query)
        );
      }
      return true;
    });
  }, [diffResult, data, riskFilter, strideFilter, searchQuery]);

  // Risk count breakdown
  const riskCounts = useMemo(() => {
    const sourceList = diffResult?.v2_analysis?.security_findings || data?.security_findings;
    if (!sourceList) return { critical: 0, high: 0, medium: 0, low: 0 };
    return sourceList.reduce(
      (acc, curr) => {
        const lvl = (curr.risk_level || '').toLowerCase();
        if (acc[lvl] !== undefined) acc[lvl]++;
        return acc;
      },
      { critical: 0, high: 0, medium: 0, low: 0 }
    );
  }, [diffResult, data]);

  // STRIDE categories list
  const strideCategories = useMemo(() => {
    const sourceList = diffResult?.v2_analysis?.security_findings || data?.security_findings;
    if (!sourceList) return [];
    return Array.from(new Set(sourceList.map((f) => f.stride_category)));
  }, [diffResult, data]);

  // Merge backend test revalidation statuses with genuine execution results
  // CRITICAL: A test that requires revalidation CANNOT continue to appear as PASSED!
  const combinedSecurityTests = useMemo(() => {
    if (!diffResult || !diffResult.security_tests) return [];
    return diffResult.security_tests.map((test) => {
      const executed = executedTestResults[test.id];
      if (
        !test.needs_revalidation &&
        executed &&
        executed.target_architecture_version === v2Architecture.system
      ) {
        return {
          ...test,
          status: executed.status,
          test_result: executed.test_result,
          execution_mode: executed.execution_mode || 'SIMULATED',
          needs_revalidation: false,
          last_run_timestamp: executed.last_run_timestamp,
          evidence: executed.evidence,
          execution_log: executed.execution_log,
        };
      }
      return {
        ...test,
        execution_mode: 'SIMULATED',
      };
    });
  }, [diffResult, executedTestResults, v2Architecture.system]);

  // Summary counts for Diff badges
  const diffSummary = useMemo(() => {
    if (!diffResult) return { addedIfaces: 0, removedIfaces: 0, modifiedIfaces: 0, newThreats: 0, revalCount: 0 };
    const addedIfaces = diffResult.changes?.interfaces?.added?.length || 0;
    const removedIfaces = diffResult.changes?.interfaces?.removed?.length || 0;
    const modifiedIfaces = diffResult.changes?.interfaces?.modified?.length || 0;
    const newThreats = diffResult.threat_delta?.new_threats?.length || 0;
    const revalCount = combinedSecurityTests.filter((t) => t.status === 'NEEDS_REVALIDATION').length;
    return { addedIfaces, removedIfaces, modifiedIfaces, newThreats, revalCount };
  }, [diffResult, combinedSecurityTests]);

  // Helpers for badge styles
  const getRiskBadgeClass = (level) => {
    switch ((level || '').toUpperCase()) {
      case 'CRITICAL':
        return 'badge badge-critical';
      case 'HIGH':
        return 'badge badge-high';
      case 'MEDIUM':
        return 'badge badge-medium';
      case 'LOW':
        return 'badge badge-low';
      default:
        return 'badge';
    }
  };

  const getStrideBadgeClass = (category) => {
    switch ((category || '').toLowerCase()) {
      case 'spoofing':
        return 'badge stride-spoofing';
      case 'tampering':
        return 'badge stride-tampering';
      case 'repudiation':
        return 'badge stride-repudiation';
      case 'information disclosure':
        return 'badge stride-information-disclosure';
      case 'denial of service':
        return 'badge stride-denial-of-service';
      case 'elevation of privilege':
        return 'badge stride-elevation-of-privilege';
      default:
        return 'badge stride-spoofing';
    }
  };

  const getProtocolBadgeClass = (protocol) => {
    switch ((protocol || '').toLowerCase()) {
      case 'can':
        return 'badge proto-can';
      case 'ethernet':
        return 'badge proto-ethernet';
      case 'bluetooth':
        return 'badge proto-bluetooth';
      case 'wi-fi':
        return 'badge proto-wifi';
      case 'usb':
        return 'badge proto-usb';
      default:
        return 'badge proto-default';
    }
  };

  const getSurfaceDomainBadgeClass = (type) => {
    switch ((type || '').toLowerCase()) {
      case 'external':
        return 'badge domain-external';
      case 'network':
        return 'badge domain-network';
      case 'internal communication':
        return 'badge domain-internal';
      case 'physical':
        return 'badge domain-physical';
      case 'service/diagnostic':
        return 'badge domain-diagnostic';
      default:
        return 'badge';
    }
  };

  // Node options for interface creation
  const nodeOptions = useMemo(() => {
    const list = v2Architecture.components.map((c) => c.id);
    if (!list.includes('external')) list.push('external');
    return list;
  }, [v2Architecture]);

  return (
    <div className="app-container">
      {/* SECTION A: HEADER */}
      <header className="dashboard-header">
        <div className="header-top">
          <div className="header-brand">
            <div className="header-logo-box">
              <Shield style={{ width: 24, height: 24 }} />
            </div>
            <div>
              <div className="header-title">
                <span>ThreatLens AI</span>
                <span className="version-pill">v1.1 Change Detection & Revalidation</span>
              </div>
              <div className="header-subtitle">
                AI-Assisted Embedded Security Validation • Architecture Delta & Threat Revalidation
              </div>
            </div>
          </div>

          <div className="header-controls">
            <div className="system-pill">
              <span className="system-pill-label">V1 Baseline:</span>
              <span className="system-pill-val">{v1Baseline.system}</span>
            </div>

            <div className="health-pill">
              <span
                className={`health-dot ${
                  healthStatus === 'connected'
                    ? 'online'
                    : healthStatus === 'checking'
                    ? 'checking'
                    : healthStatus === 'degraded'
                    ? 'degraded'
                    : 'offline'
                }`}
              />
              <span style={{ color: 'var(--text-muted)' }}>API:</span>
              <span
                style={{
                  color:
                    healthStatus === 'connected'
                      ? 'var(--accent-emerald)'
                      : healthStatus === 'checking'
                      ? 'var(--risk-medium)'
                      : healthStatus === 'degraded'
                      ? 'var(--risk-high)'
                      : 'var(--risk-critical)',
                  fontWeight: 600,
                }}
              >
                {healthStatus === 'connected'
                  ? `ONLINE (${CONFIGURED_API_PORT})`
                  : healthStatus === 'checking'
                  ? `CHECKING (${CONFIGURED_API_PORT})`
                  : healthStatus === 'degraded'
                  ? `DEGRADED (${CONFIGURED_API_PORT})`
                  : `OFFLINE (${CONFIGURED_API_PORT})`}
              </span>
            </div>

            <button
              onClick={runBaselineAnalysis}
              disabled={loading}
              className="reanalyze-button"
              title="Rerun architecture threat analysis"
            >
              <RefreshCw
                style={{
                  width: 14,
                  height: 14,
                  animation: loading ? 'spin 1s linear infinite' : 'none',
                }}
              />
              <span>{loading ? 'Analyzing...' : 'Re-Analyze'}</span>
            </button>
          </div>
        </div>

        {/* Navigation Tabs Bar */}
        <div className="nav-bar-container">
          <div className="nav-tabs-list">
            <button
              onClick={() => setActiveTab('all')}
              className={`nav-tab-item ${activeTab === 'all' ? 'active' : ''}`}
            >
              All Sections
            </button>
            <button
              onClick={() => setActiveTab('comparison')}
              className={`nav-tab-item ${activeTab === 'comparison' ? 'active' : ''}`}
            >
              <GitCompare style={{ width: 14, height: 14, display: 'inline', marginRight: 6 }} />
              Architecture Comparison & Revalidation
              {(diffSummary.addedIfaces > 0 || diffSummary.newThreats > 0 || diffSummary.revalCount > 0) && (
                <span
                  style={{
                    marginLeft: 6,
                    padding: '1px 6px',
                    borderRadius: 9999,
                    background: diffSummary.revalCount > 0 ? 'rgba(245,158,11,0.25)' : 'rgba(6,182,212,0.25)',
                    color: diffSummary.revalCount > 0 ? '#fbbf24' : 'var(--accent-cyan)',
                    fontSize: 10,
                    fontWeight: 700,
                  }}
                >
                  +{diffSummary.newThreats} New
                </span>
              )}
            </button>
            <button
              onClick={() => setActiveTab('architecture')}
              className={`nav-tab-item ${activeTab === 'architecture' ? 'active' : ''}`}
            >
              Architecture (V1 & V2)
            </button>
            <button
              onClick={() => setActiveTab('surfaces')}
              className={`nav-tab-item ${activeTab === 'surfaces' ? 'active' : ''}`}
            >
              Attack Surfaces
            </button>
            <button
              onClick={() => setActiveTab('threats')}
              className={`nav-tab-item ${activeTab === 'threats' ? 'active' : ''}`}
            >
              STRIDE Threats & Findings ({filteredFindings.length})
            </button>
            <button
              onClick={() => setActiveTab('validation')}
              className={`nav-tab-item ${activeTab === 'validation' ? 'active' : ''}`}
            >
              Security Validation Tests
              {diffSummary.revalCount > 0 && (
                <span
                  style={{
                    marginLeft: 6,
                    padding: '1px 6px',
                    borderRadius: 9999,
                    background: 'rgba(245,158,11,0.25)',
                    color: '#fbbf24',
                    fontSize: 10,
                    fontWeight: 700,
                  }}
                >
                  {diffSummary.revalCount} Need Revalidation
                </span>
              )}
            </button>
          </div>
        </div>
      </header>

      {/* MAIN CONTAINER */}
      <main className="dashboard-main">
        {/* Loading State */}
        {loading && !data && (
          <div className="state-panel">
            <RefreshCw
              style={{
                width: 36,
                height: 36,
                color: 'var(--accent-cyan)',
                animation: 'spin 1s linear infinite',
              }}
            />
            <h3 style={{ fontSize: 16, fontWeight: 700, color: '#fff' }}>
              Parsing Architecture & Running Threat Engine...
            </h3>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', maxWidth: 440 }}>
              Querying FastAPI <code style={{ color: 'var(--accent-cyan)' }}>POST /api/analyze</code>, identifying
              attack surfaces, calculating risk scores, and mapping CWE recommendations.
            </p>
          </div>
        )}

        {/* Error State */}
        {error && (
          <div className="error-banner">
            <ShieldAlert style={{ width: 24, height: 24, color: 'var(--risk-critical)', flexShrink: 0 }} />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: '#fca5a5' }}>
                Backend Communication Failure
              </div>
              <p style={{ fontSize: 12, color: '#fecaca', marginTop: 4 }}>{error}</p>
              <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 12 }}>
                <button
                  onClick={runBaselineAnalysis}
                  className="reanalyze-button"
                  style={{ background: 'var(--risk-critical)', color: '#fff', borderColor: 'transparent' }}
                >
                  Retry Connection
                </button>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  Start backend with: <code style={{ color: 'var(--accent-cyan)' }}>python backend/main.py</code> (Port {CONFIGURED_API_PORT})
                </span>
              </div>
            </div>
          </div>
        )}

        {data && (
          <>
            {/* SECTION B: SUMMARY METRICS (Horizontal Grid on Desktop) */}
            <section className="summary-grid">
              {/* Card 1: Components */}
              <div className="summary-card">
                <div className="summary-header">
                  <span>Components</span>
                  <Cpu style={{ width: 16, height: 16, color: 'var(--accent-cyan)' }} />
                </div>
                <div>
                  <div className="summary-number">
                    {diffResult?.v2_summary?.components_count || data.components?.length || 0}
                  </div>
                  <div className="summary-subtext">
                    Baseline: {data.components ? data.components.length : 0} ECUs
                  </div>
                </div>
              </div>

              {/* Card 2: Interfaces */}
              <div className="summary-card">
                <div className="summary-header">
                  <span>Interfaces</span>
                  <Network style={{ width: 16, height: 16, color: 'var(--accent-blue)' }} />
                </div>
                <div>
                  <div className="summary-number">
                    {diffResult?.v2_summary?.interfaces_count || data.interfaces?.length || 0}
                  </div>
                  <div className="summary-subtext">
                    {diffSummary.addedIfaces > 0 ? (
                      <span style={{ color: '#6ee7b7' }}>+{diffSummary.addedIfaces} Added Interface</span>
                    ) : (
                      'Buses & Radio Links'
                    )}
                  </div>
                </div>
              </div>

              {/* Card 3: Attack Surfaces */}
              <div className="summary-card">
                <div className="summary-header">
                  <span>Attack Surfaces</span>
                  <Radio style={{ width: 16, height: 16, color: '#fbbf24' }} />
                </div>
                <div>
                  <div className="summary-number">
                    {diffResult?.v2_summary?.attack_surfaces_count || data.attack_surfaces?.length || 0}
                  </div>
                  <div className="summary-subtext">
                    {diffResult?.attack_surface_delta?.added?.length > 0 ? (
                      <span style={{ color: '#fbbf24' }}>
                        +{diffResult.attack_surface_delta.added.length} New Surface
                      </span>
                    ) : (
                      'Exposure Vectors'
                    )}
                  </div>
                </div>
              </div>

              {/* Card 4: STRIDE Threats */}
              <div className="summary-card">
                <div className="summary-header">
                  <span>STRIDE Threats</span>
                  <AlertTriangle style={{ width: 16, height: 16, color: 'var(--accent-purple)' }} />
                </div>
                <div>
                  <div className="summary-number">
                    {diffResult?.v2_summary?.threats_count || data.threats?.length || 0}
                  </div>
                  <div className="summary-subtext">
                    {diffSummary.newThreats > 0 ? (
                      <span style={{ color: '#d8b4fe' }}>+{diffSummary.newThreats} New Threats</span>
                    ) : (
                      'Rule-derived Models'
                    )}
                  </div>
                </div>
              </div>

              {/* Card 5: Security Findings */}
              <div className="summary-card accent-rose">
                <div className="summary-header">
                  <span>Security Findings</span>
                  <ShieldAlert style={{ width: 16, height: 16, color: 'var(--risk-critical)' }} />
                </div>
                <div>
                  <div className="summary-number text-rose">
                    {diffResult?.v2_summary?.findings_count || data.security_findings?.length || 0}
                  </div>
                  <div className="summary-breakdown">
                    <span className="badge badge-critical">{riskCounts.critical} Crit</span>
                    <span className="badge badge-high">{riskCounts.high} High</span>
                  </div>
                </div>
              </div>
            </section>

            {/* NEW SECTION: ARCHITECTURE CHANGE DETECTION & REVALIDATION */}
            {(activeTab === 'all' || activeTab === 'comparison') && (
              <section className="dashboard-section" style={{ border: '1px solid rgba(6,182,212,0.35)' }}>
                <div className="section-head">
                  <div className="section-title-wrap">
                    <div className="section-icon-box cyan">
                      <GitCompare style={{ width: 18, height: 18 }} />
                    </div>
                    <div>
                      <h2 className="section-title">Architecture Change Detection & Security Revalidation</h2>
                      <div className="section-desc">
                        Automated Delta Analysis between V1 Baseline and V2 Working Architecture
                      </div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {isComparing && (
                      <span style={{ fontSize: 11, color: 'var(--accent-cyan)', fontFamily: 'monospace' }}>
                        Computing Delta...
                      </span>
                    )}
                    <button onClick={() => setIsEditorOpen(true)} className="btn-editor">
                      <Edit3 style={{ width: 14, height: 14 }} />
                      Edit V2 Architecture
                    </button>
                  </div>
                </div>

                {/* Version Control & Preset Toolbar */}
                <div className="version-control-bar">
                  <div className="version-labels-group">
                    <div className="version-tag baseline">
                      <span>Baseline V1:</span>
                      <strong>{v1Baseline.system}</strong>
                      <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>
                        ({v1Baseline.interfaces.length} Ifaces)
                      </span>
                    </div>

                    <ArrowRight style={{ width: 14, height: 14, color: 'var(--accent-cyan)' }} />

                    <div className="version-tag target">
                      <span>Target V2:</span>
                      <strong>{v2Architecture.system}</strong>
                      <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>
                        ({v2Architecture.interfaces.length} Ifaces)
                      </span>
                    </div>
                  </div>

                  {/* Preset Demo Buttons */}
                  <div className="version-actions-group">
                    <span style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
                      Quick Scenarios:
                    </span>
                    <button
                      onClick={handlePresetAddWifi}
                      className="btn-preset"
                      title="Add external Wi-Fi interface to Infotainment ECU"
                    >
                      <Plus style={{ width: 12, height: 12, color: 'var(--accent-cyan)' }} />
                      Add Wi-Fi Interface
                    </button>
                    <button
                      onClick={handlePresetAddDiagnostic}
                      className="btn-preset"
                      title="Add external OBD-II Service/Diagnostic port to Gateway"
                    >
                      <Plus style={{ width: 12, height: 12, color: '#fbbf24' }} />
                      Add Diagnostic Port
                    </button>
                    <button
                      onClick={handlePresetResetBaseline}
                      className="btn-preset"
                      title="Reset V2 to match V1 baseline"
                    >
                      <RotateCcw style={{ width: 12, height: 12 }} />
                      Reset to V1 Baseline
                    </button>
                  </div>
                </div>

                {comparisonError && (
                  <div className="error-banner" style={{ padding: 12 }}>
                    <ShieldAlert style={{ width: 18, height: 18, color: 'var(--risk-critical)' }} />
                    <span style={{ fontSize: 12, color: '#fca5a5' }}>{comparisonError}</span>
                  </div>
                )}

                {/* Diff Metric Cards */}
                <div className="diff-stat-cards">
                  <div className={`diff-card ${diffSummary.addedIfaces > 0 || diffSummary.removedIfaces > 0 ? 'has-changes' : ''}`}>
                    <div className="diff-card-label">
                      <span>Interface Delta</span>
                      <Network style={{ width: 14, height: 14, color: 'var(--accent-blue)' }} />
                    </div>
                    <div className="diff-card-value">
                      <span style={{ color: '#6ee7b7' }}>+{diffSummary.addedIfaces}</span>
                      <span style={{ color: 'var(--text-dim)', margin: '0 4px', fontSize: 18 }}>/</span>
                      <span style={{ color: '#fca5a5' }}>-{diffSummary.removedIfaces}</span>
                      {diffSummary.modifiedIfaces > 0 && (
                        <span style={{ color: '#fcd34d', fontSize: 14, marginLeft: 6 }}>
                          (~{diffSummary.modifiedIfaces} mod)
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                      Total in V2: {v2Architecture.interfaces.length}
                    </div>
                  </div>

                  <div className={`diff-card ${diffResult?.attack_surface_delta?.added?.length > 0 ? 'has-changes' : ''}`}>
                    <div className="diff-card-label">
                      <span>New Attack Surfaces</span>
                      <Radio style={{ width: 14, height: 14, color: '#fbbf24' }} />
                    </div>
                    <div className="diff-card-value" style={{ color: '#fbbf24' }}>
                      +{diffResult?.attack_surface_delta?.added?.length || 0}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                      Retained Surfaces: {diffResult?.attack_surface_delta?.retained_count || 0}
                    </div>
                  </div>

                  <div className={`diff-card ${diffSummary.newThreats > 0 ? 'has-changes' : ''}`}>
                    <div className="diff-card-label">
                      <span>New STRIDE Threats</span>
                      <AlertTriangle style={{ width: 14, height: 14, color: 'var(--accent-purple)' }} />
                    </div>
                    <div className="diff-card-value" style={{ color: '#d8b4fe' }}>
                      +{diffSummary.newThreats}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                      Retained: {diffResult?.threat_delta?.retained_count || 0} | Mitigated: {diffResult?.threat_delta?.removed_threats?.length || 0}
                    </div>
                  </div>

                  <div className={`diff-card ${diffSummary.revalCount > 0 ? 'has-reval' : ''}`}>
                    <div className="diff-card-label">
                      <span>Revalidation Required</span>
                      <CheckCircle2 style={{ width: 14, height: 14, color: diffSummary.revalCount > 0 ? '#fbbf24' : 'var(--accent-emerald)' }} />
                    </div>
                    <div className="diff-card-value" style={{ color: diffSummary.revalCount > 0 ? '#fbbf24' : 'var(--accent-emerald)' }}>
                      {diffSummary.revalCount}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                      Tests requiring re-execution
                    </div>
                  </div>
                </div>

                {/* Sub-grid 1: Interfaces & Attack Surface Delta */}
                <div className="architecture-grid">
                  {/* Interface Delta Details */}
                  <div>
                    <div className="sub-section-title">
                      <Network style={{ width: 14, height: 14, color: 'var(--accent-cyan)' }} />
                      <span>Interface Changes (V1 → V2)</span>
                    </div>

                    <div className="interfaces-list">
                      {/* Added interfaces */}
                      {diffResult?.changes?.interfaces?.added?.map((iface, idx) => (
                        <div key={`added-${idx}`} className="interface-item diff-row-added">
                          <div className="interface-flow">
                            <span>{iface.source}</span>
                            <ArrowRight style={{ width: 14, height: 14, color: '#10b981' }} />
                            <span>{iface.target}</span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <span className={getProtocolBadgeClass(iface.protocol)}>{iface.protocol}</span>
                            <span className="diff-badge-added">+ ADDED</span>
                          </div>
                        </div>
                      ))}

                      {/* Modified interfaces */}
                      {diffResult?.changes?.interfaces?.modified?.map((iface, idx) => (
                        <div key={`mod-${idx}`} className="interface-item diff-row-modified">
                          <div className="interface-flow">
                            <span>{iface.source}</span>
                            <ArrowRight style={{ width: 14, height: 14, color: '#f59e0b' }} />
                            <span>{iface.target}</span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <span className="badge" style={{ textDecoration: 'line-through', opacity: 0.6 }}>
                              {iface.old_protocol}
                            </span>
                            <ArrowRight style={{ width: 10, height: 10, color: '#f59e0b' }} />
                            <span className={getProtocolBadgeClass(iface.new_protocol)}>{iface.new_protocol}</span>
                            <span className="diff-badge-modified">~ MODIFIED</span>
                          </div>
                        </div>
                      ))}

                      {/* Removed interfaces */}
                      {diffResult?.changes?.interfaces?.removed?.map((iface, idx) => (
                        <div key={`rem-${idx}`} className="interface-item diff-row-removed">
                          <div className="interface-flow">
                            <span>{iface.source}</span>
                            <ArrowRight style={{ width: 14, height: 14, color: '#ef4444' }} />
                            <span>{iface.target}</span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <span className={getProtocolBadgeClass(iface.protocol)}>{iface.protocol}</span>
                            <span className="diff-badge-removed">- REMOVED</span>
                          </div>
                        </div>
                      ))}

                      {/* Unchanged count */}
                      <div
                        style={{
                          fontSize: 11,
                          fontFamily: 'monospace',
                          color: 'var(--text-dim)',
                          padding: '8px 12px',
                          background: 'rgba(15,23,42,0.5)',
                          borderRadius: 6,
                          border: '1px solid var(--border-dark)',
                        }}
                      >
                        ✓ {diffResult?.changes?.interfaces?.unchanged_count || 0} interface(s) identical to baseline V1
                      </div>
                    </div>
                  </div>

                  {/* Newly Introduced Attack Surfaces */}
                  <div>
                    <div className="sub-section-title">
                      <Radio style={{ width: 14, height: 14, color: '#fbbf24' }} />
                      <span>Newly Introduced Attack Surfaces</span>
                    </div>

                    <div className="interfaces-list">
                      {diffResult?.attack_surface_delta?.added?.length === 0 ? (
                        <div
                          style={{
                            padding: '16px',
                            background: 'rgba(15,23,42,0.5)',
                            borderRadius: 8,
                            border: '1px solid var(--border-dark)',
                            fontSize: 12,
                            color: 'var(--text-dim)',
                            textAlign: 'center',
                          }}
                        >
                          No new attack surfaces introduced in V2.
                        </div>
                      ) : (
                        diffResult?.attack_surface_delta?.added?.map((surf, idx) => (
                          <div key={`new-surf-${idx}`} className="interface-item diff-row-added">
                            <div className="interface-flow">
                              <span>{surf.source}</span>
                              <ArrowRight style={{ width: 14, height: 14, color: '#10b981' }} />
                              <span>{surf.target}</span>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                              <span className={getProtocolBadgeClass(surf.protocol)}>{surf.protocol}</span>
                              <span className={getSurfaceDomainBadgeClass(surf.type)}>{surf.type}</span>
                              <span className="diff-badge-added">+ NEW SURFACE</span>
                            </div>
                          </div>
                        ))
                      )}

                      <div
                        style={{
                          fontSize: 11,
                          fontFamily: 'monospace',
                          color: 'var(--text-dim)',
                          padding: '8px 12px',
                          background: 'rgba(15,23,42,0.5)',
                          borderRadius: 6,
                          border: '1px solid var(--border-dark)',
                        }}
                      >
                        ✓ {diffResult?.attack_surface_delta?.retained_count || 0} surface(s) retained from baseline V1
                      </div>
                    </div>
                  </div>
                </div>

                {/* Sub-grid 2: Newly Introduced STRIDE Threats */}
                <div>
                  <div className="sub-section-title">
                    <ShieldAlert style={{ width: 14, height: 14, color: 'var(--risk-critical)' }} />
                    <span>Newly Introduced STRIDE Threats ({diffResult?.threat_delta?.new_threats?.length || 0})</span>
                  </div>

                  {diffResult?.threat_delta?.new_threats?.length === 0 ? (
                    <div
                      style={{
                        padding: '24px',
                        background: 'rgba(15,23,42,0.5)',
                        borderRadius: 8,
                        border: '1px solid var(--border-dark)',
                        fontSize: 12,
                        color: 'var(--text-dim)',
                        textAlign: 'center',
                      }}
                    >
                      No new threats introduced in V2 architecture. Threat vector footprint is identical to baseline.
                    </div>
                  ) : (
                    <div className="threats-list">
                      {diffResult?.threat_delta?.new_threats?.map((finding) => (
                        <div
                          key={`new-th-${finding.threat_id}`}
                          onClick={() => setSelectedThreat(finding)}
                          className="threat-card diff-row-added"
                          style={{ cursor: 'pointer' }}
                        >
                          <div className="threat-main">
                            <div className="threat-badges-row">
                              <span className="diff-badge-added">+ NEW THREAT</span>
                              <span className="threat-id-badge">{finding.threat_id}</span>
                              <span className={getStrideBadgeClass(finding.stride_category)}>
                                {finding.stride_category}
                              </span>
                              <span className={getProtocolBadgeClass(finding.protocol)}>
                                {finding.protocol}
                              </span>
                              <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                                {finding.source} → {finding.target}
                              </span>
                            </div>

                            <div className="threat-desc">{finding.description}</div>

                            <div className="threat-meta-row">
                              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                <ShieldCheck style={{ width: 14, height: 14, color: 'var(--accent-emerald)' }} />
                                <strong style={{ color: '#fff' }}>{finding.cwe}</strong>: {finding.cwe_name}
                              </span>
                            </div>
                          </div>

                          <div className="threat-score-block">
                            <div>
                              <span className={getRiskBadgeClass(finding.risk_level)}>
                                {finding.risk_level}
                              </span>
                              <div className="threat-score-val" style={{ marginTop: 4 }}>
                                {finding.risk_score}
                                <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>/100</span>
                              </div>
                              <div className="threat-score-sub">
                                Imp:{finding.impact} Exp:{finding.exploitability}
                              </div>
                            </div>
                            <div className="threat-arrow-icon">
                              <ChevronRight style={{ width: 18, height: 18 }} />
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Sub-grid 3: Security Test Revalidation Suite */}
                <div>
                  <div className="section-head" style={{ borderBottom: 'none', paddingBottom: 0 }}>
                    <div className="sub-section-title" style={{ marginBottom: 0 }}>
                      <CheckCircle2 style={{ width: 14, height: 14, color: 'var(--accent-emerald)' }} />
                      <span>Security Test Revalidation Suite ({combinedSecurityTests.length} Tests)</span>
                      <span className="badge" style={{ background: 'rgba(59,130,246,0.15)', color: '#93c5fd', borderColor: 'rgba(59,130,246,0.3)', fontSize: 10, marginLeft: 6 }}>
                        EXECUTION: SIMULATED
                      </span>
                    </div>

                    <button
                      onClick={() => handleExecuteTests(null)}
                      disabled={isExecutingAllTests}
                      className="btn-editor"
                      style={{ background: 'rgba(16,185,129,0.15)', color: '#6ee7b7', borderColor: 'rgba(16,185,129,0.4)' }}
                    >
                      <Play style={{ width: 14, height: 14, fill: '#6ee7b7' }} />
                      {isExecutingAllTests ? 'Executing Test Suite...' : 'Execute All Revalidation Tests'}
                    </button>
                  </div>

                  {testExecutionError && (
                    <div className="error-banner" style={{ padding: 12, marginTop: 10 }}>
                      <ShieldAlert style={{ width: 18, height: 18, color: 'var(--risk-critical)' }} />
                      <span style={{ fontSize: 12, color: '#fca5a5' }}>{testExecutionError}</span>
                    </div>
                  )}

                  <div className="validation-grid" style={{ marginTop: 14 }}>
                    {combinedSecurityTests.map((tc) => {
                      const isExecuting = executingTestId === tc.id;
                      const hasLog = Boolean(tc.execution_log);
                      const isExpanded = expandedLogTestId === tc.id;

                      return (
                        <div
                          key={`reval-tc-${tc.id}`}
                          className={`reval-card ${
                            tc.status === 'NEEDS_REVALIDATION'
                              ? 'needs-reval'
                              : tc.status === 'PASSED'
                              ? 'passed'
                              : ''
                          }`}
                        >
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                            <div className="val-card-top">
                              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                <span className="val-card-id">{tc.id}</span>
                                <span className="badge" style={{ fontSize: 9, background: 'rgba(255,255,255,0.06)', color: 'var(--text-dim)' }}>
                                  SIMULATED
                                </span>
                              </div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                {tc.status === 'NEEDS_REVALIDATION' ? (
                                  <span className="reval-badge-needs">
                                    <AlertTriangle style={{ width: 12, height: 12 }} />
                                    Needs Revalidation
                                  </span>
                                ) : tc.status === 'PASSED' ? (
                                  <span className="reval-badge-passed">
                                    <CheckCircle2 style={{ width: 12, height: 12 }} />
                                    PASSED [SIMULATED]
                                  </span>
                                ) : tc.status === 'NOT_APPLICABLE' ? (
                                  <span className="reval-badge-notrun">Not Applicable</span>
                                ) : (
                                  <span className="reval-badge-notrun">Not Run</span>
                                )}

                                <button
                                  onClick={() => handleExecuteTests([tc.id])}
                                  disabled={isExecuting || isExecutingAllTests}
                                  className="btn-preset"
                                  style={{ padding: '4px 8px', fontSize: 10 }}
                                  title="Execute simulated security test harness"
                                >
                                  <Play style={{ width: 10, height: 10 }} />
                                  {isExecuting ? 'Running...' : 'Run Test'}
                                </button>
                              </div>
                            </div>

                            <h4 className="val-card-title">{tc.name}</h4>

                            <div style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: 'monospace' }}>
                              Target Protocols: <span style={{ color: 'var(--accent-cyan)' }}>{tc.target_protocols.join(', ')}</span>
                            </div>

                            {/* Reason for status */}
                            <div
                              style={{
                                fontSize: 11,
                                padding: '6px 10px',
                                borderRadius: 6,
                                background:
                                  tc.status === 'NEEDS_REVALIDATION'
                                    ? 'rgba(245,158,11,0.1)'
                                    : 'rgba(15,23,42,0.6)',
                                border: `1px solid ${
                                  tc.status === 'NEEDS_REVALIDATION'
                                    ? 'rgba(245,158,11,0.3)'
                                    : 'var(--border-dark)'
                                }`,
                                color:
                                  tc.status === 'NEEDS_REVALIDATION'
                                    ? '#fde68a'
                                    : 'var(--text-dim)',
                              }}
                            >
                              <strong>Impact Assessment:</strong> {tc.reason}
                            </div>
                          </div>

                          <div className="val-field-box">
                            <div>
                              <span className="val-field-label">Objective:</span>
                              <div style={{ color: '#cbd5e1', marginTop: 2 }}>{tc.objective}</div>
                            </div>
                            <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 6, marginTop: 4 }}>
                              <span className="val-field-label">Expected Result:</span>
                              <div className="val-field-expected" style={{ marginTop: 2 }}>
                                {tc.expected_result}
                              </div>
                            </div>
                          </div>

                          {/* Simulated Evidence */}
                          {tc.evidence && (
                            <div className="val-field-box" style={{ background: 'rgba(6,182,212,0.05)', borderColor: 'rgba(6,182,212,0.2)' }}>
                              <span className="val-field-label" style={{ color: 'var(--accent-cyan)' }}>Validation Evidence & Hardware Notice:</span>
                              <div style={{ color: '#93c5fd', fontSize: 11, marginTop: 2, lineHeight: 1.4 }}>
                                {tc.evidence}
                              </div>
                            </div>
                          )}

                          {/* Recorded Execution Details */}
                          {tc.last_run_timestamp && (
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 10, fontFamily: 'monospace', color: 'var(--text-dim)', flexWrap: 'wrap', gap: 6 }}>
                              <span>Version: <strong style={{ color: '#fff' }}>{tc.target_architecture_version || v2Architecture.system}</strong> • Executed: {new Date(tc.last_run_timestamp).toLocaleTimeString()}</span>
                              <button
                                onClick={() => setExpandedLogTestId(isExpanded ? null : tc.id)}
                                style={{ background: 'transparent', border: 'none', color: 'var(--accent-cyan)', cursor: 'pointer', fontSize: 11 }}
                              >
                                {isExpanded ? 'Hide Test Log' : 'View Test Log'}
                              </button>
                            </div>
                          )}

                          {isExpanded && tc.execution_log && (
                            <pre className="test-log-terminal">{tc.execution_log}</pre>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              </section>
            )}

            {/* SECTION C: ARCHITECTURE SECTION */}
            {(activeTab === 'all' || activeTab === 'architecture') && (
              <section className="dashboard-section">
                <div className="section-head">
                  <div className="section-title-wrap">
                    <div className="section-icon-box cyan">
                      <Layers style={{ width: 18, height: 18 }} />
                    </div>
                    <div>
                      <h2 className="section-title">Vehicle System Architecture</h2>
                      <div className="section-desc">
                        Active Target Topology: <strong style={{ color: 'var(--accent-cyan)' }}>{v2Architecture.system}</strong>
                      </div>
                    </div>
                  </div>
                  <div className="section-stat-pill">
                    {v2Architecture.components.length} Controller Nodes • {v2Architecture.interfaces.length} Bus Links
                  </div>
                </div>

                <div className="architecture-grid">
                  {/* Left Column: Components */}
                  <div>
                    <div className="sub-section-title">
                      <Cpu style={{ width: 14, height: 14, color: 'var(--accent-cyan)' }} />
                      <span>Components & ECUs ({v2Architecture.components.length})</span>
                    </div>
                    <div className="ecu-cards-grid">
                      {v2Architecture.components.map((comp) => (
                        <div key={comp.id} className="ecu-card">
                          <div className="ecu-top">
                            <span className="ecu-name">{comp.name}</span>
                            <span className="badge" style={{ background: 'rgba(6,182,212,0.12)', color: 'var(--accent-cyan)', borderColor: 'rgba(6,182,212,0.3)' }}>
                              {comp.type || 'ECU'}
                            </span>
                          </div>
                          <div className="ecu-id-row">
                            <span>ID:</span>
                            <span style={{ color: '#fff', fontWeight: 600 }}>{comp.id}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Right Column: Interfaces */}
                  <div>
                    <div className="sub-section-title">
                      <Network style={{ width: 14, height: 14, color: 'var(--accent-blue)' }} />
                      <span>Communication Interfaces ({v2Architecture.interfaces.length})</span>
                    </div>
                    <div className="interfaces-list">
                      {v2Architecture.interfaces.map((iface, idx) => (
                        <div key={idx} className="interface-item">
                          <div className="interface-flow">
                            <span>{iface.source}</span>
                            <ArrowRight style={{ width: 14, height: 14, color: 'var(--accent-cyan)' }} />
                            <span>{iface.target}</span>
                          </div>
                          <span className={getProtocolBadgeClass(iface.protocol)}>
                            {iface.protocol}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </section>
            )}

            {/* SECTION D: ATTACK SURFACE SECTION */}
            {(activeTab === 'all' || activeTab === 'surfaces') && (
              <section className="dashboard-section">
                <div className="section-head">
                  <div className="section-title-wrap">
                    <div className="section-icon-box amber">
                      <Radio style={{ width: 18, height: 18 }} />
                    </div>
                    <div>
                      <h2 className="section-title">Identified Attack Surfaces</h2>
                      <div className="section-desc">
                        Mapped from interface topologies to threat exposure boundaries
                      </div>
                    </div>
                  </div>
                  <div className="section-stat-pill">
                    {diffResult?.v2_analysis?.attack_surfaces?.length || data.attack_surfaces.length} Surface Boundaries
                  </div>
                </div>

                <div className="table-container">
                  <table className="surface-table">
                    <thead>
                      <tr>
                        <th>Protocol</th>
                        <th>Source Node</th>
                        <th style={{ textAlign: 'center' }}>Direction</th>
                        <th>Target Node</th>
                        <th>Surface Domain / Type</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(diffResult?.v2_analysis?.attack_surfaces || data.attack_surfaces).map((surf, idx) => (
                        <tr key={idx}>
                          <td>
                            <span className={getProtocolBadgeClass(surf.protocol)}>
                              {surf.protocol}
                            </span>
                          </td>
                          <td style={{ color: '#fff', fontWeight: 600 }}>{surf.source}</td>
                          <td style={{ textAlign: 'center' }}>
                            <ArrowRight style={{ width: 14, height: 14, color: 'var(--accent-cyan)', display: 'inline' }} />
                          </td>
                          <td style={{ color: '#fff', fontWeight: 600 }}>{surf.target}</td>
                          <td>
                            <span className={getSurfaceDomainBadgeClass(surf.type)}>
                              {surf.type}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            )}

            {/* SECTION E & F: THREAT ANALYSIS & FILTERING */}
            {(activeTab === 'all' || activeTab === 'threats') && (
              <section className="dashboard-section">
                <div className="section-head">
                  <div className="section-title-wrap">
                    <div className="section-icon-box rose">
                      <ShieldAlert style={{ width: 18, height: 18 }} />
                    </div>
                    <div>
                      <h2 className="section-title">Threat Analysis & Risk Quantification</h2>
                      <div className="section-desc">
                        STRIDE Model synthesis with CVSS-grounded composite risk scoring and CWE taxonomy
                      </div>
                    </div>
                  </div>
                  <div className="section-stat-pill">
                    Showing <strong style={{ color: 'var(--accent-cyan)' }}>{filteredFindings.length}</strong> findings
                  </div>
                </div>

                {/* Filter Controls Bar */}
                <div className="filter-box">
                  <div className="search-row">
                    <div className="search-field">
                      <Search className="search-icon" />
                      <input
                        type="text"
                        placeholder="Filter by threat, protocol, component, CWE..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="search-input"
                      />
                    </div>

                    {(riskFilter !== 'ALL' || strideFilter !== 'ALL' || searchQuery !== '') && (
                      <button
                        onClick={() => {
                          setRiskFilter('ALL');
                          setStrideFilter('ALL');
                          setSearchQuery('');
                        }}
                        className="clear-filter-btn"
                      >
                        <X style={{ width: 12, height: 12 }} />
                        Clear Filters
                      </button>
                    )}
                  </div>

                  <div className="filter-pills-row">
                    {/* Risk Filter */}
                    <div className="filter-group">
                      <span className="filter-group-label">
                        <Filter style={{ width: 12, height: 12, display: 'inline', marginRight: 4 }} />
                        Risk:
                      </span>
                      {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
                        <button
                          key={lvl}
                          onClick={() => setRiskFilter(lvl)}
                          className={`filter-pill ${riskFilter === lvl ? 'active-risk' : ''}`}
                        >
                          {lvl}
                        </button>
                      ))}
                    </div>

                    {/* STRIDE Filter */}
                    <div className="filter-group">
                      <span className="filter-group-label">STRIDE:</span>
                      <button
                        onClick={() => setStrideFilter('ALL')}
                        className={`filter-pill ${strideFilter === 'ALL' ? 'active-stride' : ''}`}
                      >
                        ALL
                      </button>
                      {strideCategories.map((cat) => (
                        <button
                          key={cat}
                          onClick={() => setStrideFilter(cat)}
                          className={`filter-pill ${strideFilter === cat ? 'active-stride' : ''}`}
                        >
                          {cat}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Threats Cards List */}
                <div className="threats-list">
                  {filteredFindings.length === 0 ? (
                    <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-dim)', fontSize: 13 }}>
                      No security findings match your current filters.
                    </div>
                  ) : (
                    filteredFindings.map((finding) => (
                      <div
                        key={finding.threat_id}
                        onClick={() => setSelectedThreat(finding)}
                        className="threat-card"
                      >
                        <div className="threat-main">
                          <div className="threat-badges-row">
                            <span className="threat-id-badge">{finding.threat_id}</span>
                            <span className={getStrideBadgeClass(finding.stride_category)}>
                              {finding.stride_category}
                            </span>
                            <span className={getProtocolBadgeClass(finding.protocol)}>
                              {finding.protocol}
                            </span>
                            <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                              {finding.source} → {finding.target}
                            </span>
                          </div>

                          <div className="threat-desc">{finding.description}</div>

                          <div className="threat-meta-row">
                            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                              <ShieldCheck style={{ width: 14, height: 14, color: 'var(--accent-emerald)' }} />
                              <strong style={{ color: '#fff' }}>{finding.cwe}</strong>: {finding.cwe_name}
                            </span>
                          </div>
                        </div>

                        <div className="threat-score-block">
                          <div>
                            <span className={getRiskBadgeClass(finding.risk_level)}>
                              {finding.risk_level}
                            </span>
                            <div className="threat-score-val" style={{ marginTop: 4 }}>
                              {finding.risk_score}
                              <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>/100</span>
                            </div>
                            <div className="threat-score-sub">
                              Imp:{finding.impact} Exp:{finding.exploitability}
                            </div>
                          </div>

                          <div className="threat-arrow-icon">
                            <ChevronRight style={{ width: 18, height: 18 }} />
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </section>
            )}

            {/* SECTION H: SECURITY VALIDATION TEST CASES */}
            {(activeTab === 'all' || activeTab === 'validation') && (
              <section className="dashboard-section">
                <div className="section-head">
                  <div className="section-title-wrap">
                    <div className="section-icon-box emerald">
                      <CheckCircle2 style={{ width: 18, height: 18 }} />
                    </div>
                    <div>
                      <h2 className="section-title">Automated Security Validation Test Suites</h2>
                      <div className="section-desc">
                        Executable embedded security validation test scenarios generated from threat models
                      </div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className="badge" style={{ background: 'rgba(59,130,246,0.15)', color: '#93c5fd', borderColor: 'rgba(59,130,246,0.3)', fontSize: 10 }}>
                      EXECUTION: SIMULATED
                    </span>
                    <button
                      onClick={() => handleExecuteTests(null)}
                      disabled={isExecutingAllTests}
                      className="btn-editor"
                      style={{ background: 'rgba(16,185,129,0.15)', color: '#6ee7b7', borderColor: 'rgba(16,185,129,0.4)' }}
                    >
                      <Play style={{ width: 14, height: 14, fill: '#6ee7b7' }} />
                      {isExecutingAllTests ? 'Executing All Tests...' : 'Run All Validation Tests'}
                    </button>
                  </div>
                </div>

                {testExecutionError && (
                  <div className="error-banner" style={{ padding: 12, marginTop: 10 }}>
                    <ShieldAlert style={{ width: 18, height: 18, color: 'var(--risk-critical)' }} />
                    <span style={{ fontSize: 12, color: '#fca5a5' }}>{testExecutionError}</span>
                  </div>
                )}

                <div className="validation-grid">
                  {combinedSecurityTests.map((tc) => {
                    const isExecuting = executingTestId === tc.id;
                    const isExpanded = expandedLogTestId === tc.id;

                    return (
                      <div
                        key={tc.id}
                        className={`validation-card ${
                          tc.status === 'NEEDS_REVALIDATION'
                            ? 'needs-reval'
                            : tc.status === 'PASSED'
                            ? 'passed'
                            : ''
                        }`}
                      >
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                          <div className="val-card-top">
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                              <span className="val-card-id">{tc.id}</span>
                              <span className="badge" style={{ fontSize: 9, background: 'rgba(255,255,255,0.06)', color: 'var(--text-dim)' }}>
                                SIMULATED
                              </span>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                              {tc.status === 'NEEDS_REVALIDATION' ? (
                                <span className="reval-badge-needs">
                                  <AlertTriangle style={{ width: 12, height: 12 }} />
                                  Needs Revalidation
                                </span>
                              ) : tc.status === 'PASSED' ? (
                                <span className="reval-badge-passed">
                                  <CheckCircle2 style={{ width: 12, height: 12 }} />
                                  PASSED [SIMULATED]
                                </span>
                              ) : tc.status === 'NOT_APPLICABLE' ? (
                                <span className="reval-badge-notrun">Not Applicable</span>
                              ) : (
                                <span className="reval-badge-notrun">Not Run</span>
                              )}

                              <button
                                onClick={() => handleExecuteTests([tc.id])}
                                disabled={isExecuting || isExecutingAllTests}
                                className="btn-preset"
                                style={{ padding: '4px 8px', fontSize: 10 }}
                              >
                                <Play style={{ width: 10, height: 10 }} />
                                {isExecuting ? 'Running...' : 'Run'}
                              </button>
                            </div>
                          </div>

                          <h4 className="val-card-title">{tc.name}</h4>

                          <div style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: 'monospace' }}>
                            Target Protocols: <span style={{ color: 'var(--accent-cyan)' }}>{tc.target_protocols.join(', ')}</span>
                          </div>

                          <div
                            style={{
                              fontSize: 11,
                              padding: '6px 10px',
                              borderRadius: 6,
                              background:
                                tc.status === 'NEEDS_REVALIDATION'
                                  ? 'rgba(245,158,11,0.1)'
                                  : 'rgba(15,23,42,0.6)',
                              border: `1px solid ${
                                tc.status === 'NEEDS_REVALIDATION'
                                  ? 'rgba(245,158,11,0.3)'
                                  : 'var(--border-dark)'
                              }`,
                              color:
                                tc.status === 'NEEDS_REVALIDATION'
                                  ? '#fde68a'
                                  : 'var(--text-dim)',
                            }}
                          >
                            <strong>Status Reason:</strong> {tc.reason}
                          </div>
                        </div>

                        <div className="val-field-box">
                          <div>
                            <span className="val-field-label">Objective:</span>
                            <div style={{ color: '#cbd5e1', marginTop: 2 }}>{tc.objective}</div>
                          </div>
                          <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 6, marginTop: 4 }}>
                            <span className="val-field-label">Expected Result:</span>
                            <div className="val-field-expected" style={{ marginTop: 2 }}>
                              {tc.expected_result}
                            </div>
                          </div>
                        </div>

                        {/* Simulated Evidence */}
                        {tc.evidence && (
                          <div className="val-field-box" style={{ background: 'rgba(6,182,212,0.05)', borderColor: 'rgba(6,182,212,0.2)' }}>
                            <span className="val-field-label" style={{ color: 'var(--accent-cyan)' }}>Validation Evidence & Hardware Notice:</span>
                            <div style={{ color: '#93c5fd', fontSize: 11, marginTop: 2, lineHeight: 1.4 }}>
                              {tc.evidence}
                            </div>
                          </div>
                        )}

                        {tc.last_run_timestamp && (
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 10, fontFamily: 'monospace', color: 'var(--text-dim)', flexWrap: 'wrap', gap: 6 }}>
                            <span>Version: <strong style={{ color: '#fff' }}>{tc.target_architecture_version || v2Architecture.system}</strong> • Executed: {new Date(tc.last_run_timestamp).toLocaleTimeString()}</span>
                            <button
                              onClick={() => setExpandedLogTestId(isExpanded ? null : tc.id)}
                              style={{ background: 'transparent', border: 'none', color: 'var(--accent-cyan)', cursor: 'pointer', fontSize: 11 }}
                            >
                              {isExpanded ? 'Hide Log' : 'View Execution Log'}
                            </button>
                          </div>
                        )}

                        {isExpanded && tc.execution_log && (
                          <pre className="test-log-terminal">{tc.execution_log}</pre>
                        )}
                      </div>
                    );
                  })}
                </div>
              </section>
            )}
          </>
        )}
      </main>

      {/* ARCHITECTURE EDITOR MODAL */}
      {isEditorOpen && (
        <div className="modal-backdrop" onClick={() => setIsEditorOpen(false)}>
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 740 }}>
            <div className="modal-head">
              <div>
                <h3 style={{ fontSize: 17, fontWeight: 700, color: '#fff' }}>
                  V2 Architecture Editor
                </h3>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                  Add, remove, or modify components and interfaces to test change detection.
                </div>
              </div>
              <button onClick={() => setIsEditorOpen(false)} className="modal-close-btn">
                <X style={{ width: 18, height: 18 }} />
              </button>
            </div>

            {editorValidationMsg && (
              <div className="error-banner" style={{ padding: 10 }}>
                <span style={{ fontSize: 12, color: '#fca5a5' }}>{editorValidationMsg}</span>
              </div>
            )}

            {/* Architecture System Name */}
            <div className="detail-block">
              <span className="detail-label">System Architecture Title:</span>
              <input
                type="text"
                value={v2Architecture.system}
                onChange={(e) => {
                  const updated = { ...v2Architecture, system: e.target.value };
                  applyV2Change(updated);
                }}
                className="editor-field-input"
              />
            </div>

            {/* Interface Manager */}
            <div className="detail-block">
              <span className="detail-label">Interfaces ({v2Architecture.interfaces.length}):</span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 180, overflowY: 'auto' }}>
                {v2Architecture.interfaces.map((iface, idx) => (
                  <div key={idx} className="interface-item" style={{ padding: '8px 12px' }}>
                    <div className="interface-flow" style={{ fontSize: 12 }}>
                      <span>{iface.source}</span>
                      <ArrowRight style={{ width: 12, height: 12, color: 'var(--accent-cyan)' }} />
                      <span>{iface.target}</span>
                      <span className={getProtocolBadgeClass(iface.protocol)} style={{ fontSize: 10 }}>
                        {iface.protocol}
                      </span>
                    </div>
                    <button
                      onClick={() => handleRemoveInterface(idx)}
                      className="btn-preset"
                      style={{ padding: '3px 8px', color: '#fca5a5', borderColor: 'rgba(239,68,68,0.3)' }}
                      title="Remove Interface"
                    >
                      <Trash2 style={{ width: 12, height: 12 }} />
                      Remove
                    </button>
                  </div>
                ))}
              </div>

              {/* Add Interface Inline Row */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: 8, marginTop: 10, background: 'rgba(15,23,42,0.7)', padding: 10, borderRadius: 8, border: '1px solid var(--border-dark)' }}>
                <div>
                  <span style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block' }}>Source</span>
                  <select
                    value={newIfaceSource}
                    onChange={(e) => setNewIfaceSource(e.target.value)}
                    className="editor-field-input"
                    style={{ width: '100%', marginTop: 4 }}
                  >
                    {nodeOptions.map((n) => (
                      <option key={n} value={n}>{n}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <span style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block' }}>Target</span>
                  <select
                    value={newIfaceTarget}
                    onChange={(e) => setNewIfaceTarget(e.target.value)}
                    className="editor-field-input"
                    style={{ width: '100%', marginTop: 4 }}
                  >
                    {nodeOptions.map((n) => (
                      <option key={n} value={n}>{n}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <span style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block' }}>Protocol</span>
                  <select
                    value={newIfaceProtocol}
                    onChange={(e) => setNewIfaceProtocol(e.target.value)}
                    className="editor-field-input"
                    style={{ width: '100%', marginTop: 4 }}
                  >
                    <option value="CAN">CAN</option>
                    <option value="Ethernet">Ethernet</option>
                    <option value="Bluetooth">Bluetooth</option>
                    <option value="Wi-Fi">Wi-Fi</option>
                    <option value="USB">USB</option>
                    <option value="Diagnostic">Diagnostic</option>
                  </select>
                </div>

                <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                  <button onClick={handleAddInterface} className="btn-editor" style={{ padding: '8px 12px' }}>
                    <Plus style={{ width: 14, height: 14 }} />
                    Add
                  </button>
                </div>
              </div>
            </div>

            {/* Component Manager */}
            <div className="detail-block">
              <span className="detail-label">Components ({v2Architecture.components.length}):</span>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8, maxHeight: 150, overflowY: 'auto' }}>
                {v2Architecture.components.map((comp) => (
                  <div key={comp.id} className="ecu-card" style={{ padding: 10 }}>
                    <div className="ecu-top">
                      <span className="ecu-name" style={{ fontSize: 12 }}>{comp.name}</span>
                      <button
                        onClick={() => handleRemoveComponent(comp.id)}
                        className="modal-close-btn"
                        style={{ padding: 3, color: '#fca5a5' }}
                        title="Remove component"
                      >
                        <Trash2 style={{ width: 12, height: 12 }} />
                      </button>
                    </div>
                    <div className="ecu-id-row">
                      <span>ID:</span>
                      <span style={{ color: '#fff' }}>{comp.id}</span>
                      <span className="badge" style={{ fontSize: 9, marginLeft: 'auto' }}>{comp.type}</span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Add Component Row */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.5fr 1fr auto', gap: 8, marginTop: 10, background: 'rgba(15,23,42,0.7)', padding: 10, borderRadius: 8, border: '1px solid var(--border-dark)' }}>
                <div>
                  <span style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block' }}>ID</span>
                  <input
                    type="text"
                    placeholder="e.g. tcu"
                    value={newCompId}
                    onChange={(e) => setNewCompId(e.target.value)}
                    className="editor-field-input"
                    style={{ width: '100%', marginTop: 4 }}
                  />
                </div>
                <div>
                  <span style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block' }}>Name</span>
                  <input
                    type="text"
                    placeholder="e.g. Telematics ECU"
                    value={newCompName}
                    onChange={(e) => setNewCompName(e.target.value)}
                    className="editor-field-input"
                    style={{ width: '100%', marginTop: 4 }}
                  />
                </div>
                <div>
                  <span style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block' }}>Type</span>
                  <select
                    value={newCompType}
                    onChange={(e) => setNewCompType(e.target.value)}
                    className="editor-field-input"
                    style={{ width: '100%', marginTop: 4 }}
                  >
                    <option value="ECU">ECU</option>
                    <option value="Gateway">Gateway</option>
                    <option value="Sensor">Sensor</option>
                    <option value="Actuator">Actuator</option>
                  </select>
                </div>
                <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                  <button onClick={handleAddComponent} className="btn-editor" style={{ padding: '8px 12px' }}>
                    <Plus style={{ width: 14, height: 14 }} />
                    Add
                  </button>
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', paddingTop: 8 }}>
              <button onClick={() => setIsEditorOpen(false)} className="reanalyze-button">
                Done & Apply Changes
              </button>
            </div>
          </div>
        </div>
      )}

      {/* SECTION G: THREAT DETAIL MODAL */}
      {selectedThreat && (
        <div className="modal-backdrop" onClick={() => setSelectedThreat(null)}>
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <span className="threat-id-badge">{selectedThreat.threat_id}</span>
                  <span className={getStrideBadgeClass(selectedThreat.stride_category)}>
                    {selectedThreat.stride_category}
                  </span>
                  <span className={getRiskBadgeClass(selectedThreat.risk_level)}>
                    {selectedThreat.risk_level} Risk
                  </span>
                </div>
                <h3 style={{ fontSize: 17, fontWeight: 700, color: '#ffffff', marginTop: 4 }}>
                  {selectedThreat.stride_category} on {selectedThreat.protocol} Bus
                </h3>
              </div>
              <button
                onClick={() => setSelectedThreat(null)}
                className="modal-close-btn"
                title="Close"
              >
                <X style={{ width: 18, height: 18 }} />
              </button>
            </div>

            {/* Mathematical Risk Breakdown */}
            <div className="risk-breakdown-card">
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, fontWeight: 700, textTransform: 'uppercase', color: '#fff', letterSpacing: '0.05em' }}>
                  <Activity style={{ width: 16, height: 16, color: 'var(--accent-cyan)' }} />
                  Quantitative Risk Scoring Model
                </div>
                <div style={{ marginLeft: 'auto', fontFamily: 'monospace', fontSize: 16, fontWeight: 700, color: '#fff' }}>
                  Score: <span style={{ color: 'var(--accent-cyan)' }}>{selectedThreat.risk_score}</span> / 100
                </div>
              </div>

              <div className="risk-factors-grid">
                <div className="risk-factor-box">
                  <div className="factor-name">Impact (50%)</div>
                  <div className="factor-num" style={{ color: 'var(--risk-critical)' }}>
                    {selectedThreat.impact}
                  </div>
                  <div className="factor-sub">Severity: {selectedThreat.severity}</div>
                </div>
                <div className="risk-factor-box">
                  <div className="factor-name">Exploitability (30%)</div>
                  <div className="factor-num" style={{ color: 'var(--risk-high)' }}>
                    {selectedThreat.exploitability}
                  </div>
                  <div className="factor-sub">Protocol: {selectedThreat.protocol}</div>
                </div>
                <div className="risk-factor-box">
                  <div className="factor-name">Exposure (20%)</div>
                  <div className="factor-num" style={{ color: 'var(--accent-cyan)' }}>
                    {selectedThreat.exposure}
                  </div>
                  <div className="factor-sub">Domain: {selectedThreat.type || 'Standard'}</div>
                </div>
              </div>
            </div>

            {/* Attack Vector & Topology */}
            <div className="detail-block">
              <span className="detail-label">Attack Vector & Path:</span>
              <div className="detail-box" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontFamily: 'monospace' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ color: '#fff', fontWeight: 600 }}>{selectedThreat.source}</span>
                  <ArrowRight style={{ width: 14, height: 14, color: 'var(--accent-cyan)' }} />
                  <span style={{ color: '#fff', fontWeight: 600 }}>{selectedThreat.target}</span>
                </div>
                <span className={getProtocolBadgeClass(selectedThreat.protocol)}>
                  {selectedThreat.protocol} Interface
                </span>
              </div>
            </div>

            {/* Threat Description */}
            <div className="detail-block">
              <span className="detail-label">Threat Description:</span>
              <div className="detail-box">{selectedThreat.description}</div>
            </div>

            {/* Engineering Mitigation */}
            <div className="detail-block">
              <span className="detail-label" style={{ color: 'var(--accent-emerald)' }}>
                <ShieldCheck style={{ width: 14, height: 14 }} />
                Engineering Mitigation Recommendation:
              </span>
              <div className="detail-box mitigation">{selectedThreat.mitigation}</div>
            </div>

            {/* CWE Standard Mapping */}
            <div className="detail-block">
              <span className="detail-label">Common Weakness Enumeration (CWE) Mapping:</span>
              <div className="detail-box" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontFamily: 'monospace' }}>
                  <span style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>{selectedThreat.cwe}</span>
                  <span style={{ color: '#fff', fontWeight: 600 }}>{selectedThreat.cwe_name}</span>
                </div>
                <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 6, fontSize: 11, color: 'var(--text-muted)' }}>
                  <strong style={{ color: '#fff' }}>CWE Recommendation:</strong> {selectedThreat.cwe_recommendation}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', paddingTop: 8 }}>
              <button
                onClick={() => setSelectedThreat(null)}
                className="reanalyze-button"
                style={{ background: 'rgba(255,255,255,0.08)', color: '#fff', borderColor: 'var(--border-dark)' }}
              >
                Close Details
              </button>
            </div>
          </div>
        </div>
      )}

      {/* FOOTER */}
      <footer className="dashboard-footer">
        ThreatLens-AI • Embedded Automotive Threat Modeler & Security Validation Suite
      </footer>
    </div>
  );
}
