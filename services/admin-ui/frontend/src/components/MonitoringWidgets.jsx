/**
 * Open NAC — Admin UI Dashboard Monitoring Widgets
 * =================================================
 * Drop-in React component for the Admin UI Overview page.
 * Fetches live metrics from Prometheus and displays ISE-style widgets.
 *
 * Integration:
 *   1. Copy to admin-ui/src/components/MonitoringWidgets.jsx
 *   2. Import in your Overview/Dashboard page:
 *      import MonitoringWidgets from './MonitoringWidgets';
 *   3. Add <MonitoringWidgets /> to your layout
 *   4. Ensure Nginx proxies /api/prometheus → http://prometheus:9090
 *      (see nginx.conf snippet below)
 */

import React, { useState, useEffect, useCallback } from 'react';

const PROMETHEUS_BASE = '/api/prometheus';
const REFRESH_INTERVAL = 15000; // 15s

// ---------------------------------------------------------------------------
// Prometheus query helper
// ---------------------------------------------------------------------------
async function queryPrometheus(promql) {
  try {
    const resp = await fetch(
      `${PROMETHEUS_BASE}/api/v1/query?query=${encodeURIComponent(promql)}`
    );
    const data = await resp.json();
    if (data.status === 'success' && data.data.result.length > 0) {
      return data.data.result;
    }
    return null;
  } catch (err) {
    console.error('Prometheus query failed:', promql, err);
    return null;
  }
}

async function queryValue(promql) {
  const result = await queryPrometheus(promql);
  if (result && result[0]?.value?.[1]) {
    return parseFloat(result[0].value[1]);
  }
  return null;
}

// ---------------------------------------------------------------------------
// Status badge
// ---------------------------------------------------------------------------
function StatusBadge({ value, okLabel = 'Healthy', failLabel = 'Down' }) {
  const isOk = value === 1;
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 10px',
        borderRadius: '12px',
        fontSize: '12px',
        fontWeight: 600,
        color: '#fff',
        backgroundColor: isOk ? '#22c55e' : '#ef4444',
      }}
    >
      {isOk ? okLabel : failLabel}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Metric card
// ---------------------------------------------------------------------------
function MetricCard({ title, value, unit, color, icon, subtitle, children }) {
  return (
    <div
      style={{
        background: '#fff',
        borderRadius: '12px',
        padding: '20px',
        boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
        border: '1px solid #e5e7eb',
        minWidth: '200px',
        flex: '1 1 220px',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontSize: '13px', color: '#6b7280', fontWeight: 500, marginBottom: '4px' }}>
            {title}
          </div>
          <div style={{ fontSize: '28px', fontWeight: 700, color: color || '#111827' }}>
            {value !== null && value !== undefined ? value : '—'}
            {unit && (
              <span style={{ fontSize: '14px', fontWeight: 400, color: '#9ca3af', marginLeft: '4px' }}>
                {unit}
              </span>
            )}
          </div>
          {subtitle && (
            <div style={{ fontSize: '12px', color: '#9ca3af', marginTop: '2px' }}>{subtitle}</div>
          )}
        </div>
        {icon && <div style={{ fontSize: '24px', opacity: 0.5 }}>{icon}</div>}
      </div>
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Service status row
// ---------------------------------------------------------------------------
function ServiceStatusGrid({ services }) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))',
        gap: '8px',
        marginTop: '8px',
      }}
    >
      {services.map((svc) => (
        <div
          key={svc.name}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '8px 12px',
            borderRadius: '8px',
            background: svc.up === 1 ? '#f0fdf4' : '#fef2f2',
            border: `1px solid ${svc.up === 1 ? '#bbf7d0' : '#fecaca'}`,
          }}
        >
          <span style={{ fontSize: '13px', fontWeight: 500 }}>{svc.name}</span>
          <StatusBadge value={svc.up} />
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Widget Component
// ---------------------------------------------------------------------------
export default function MonitoringWidgets() {
  const [metrics, setMetrics] = useState({
    services: [],
    cpuPercent: null,
    memPercent: null,
    diskPercent: null,
    authPerSec: null,
    rejectRate: null,
    connectedEndpoints: null,
    galeraClusterSize: null,
    galeraReady: null,
    kafkaLag: null,
    activeAlerts: null,
    certDaysLeft: null,
  });
  const [lastUpdate, setLastUpdate] = useState(null);

  const fetchMetrics = useCallback(async () => {
    const [
      cpu,
      mem,
      disk,
      authRate,
      rejectPct,
      endpoints,
      galeraSize,
      galeraRdy,
      kafkaLagVal,
      certDays,
    ] = await Promise.all([
      queryValue('100 - (avg(irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)'),
      queryValue('(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100'),
      queryValue('(1 - node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100'),
      queryValue('rate(freeradius_total_access_requests[1m])'),
      queryValue('100 * rate(freeradius_total_access_rejects[5m]) / (rate(freeradius_total_access_accepts[5m]) + rate(freeradius_total_access_rejects[5m]) + 0.001)'),
      queryValue('policy_engine_connected_endpoints'),
      queryValue('mysql_global_status_wsrep_cluster_size'),
      queryValue('mysql_global_status_wsrep_ready'),
      queryValue('max(kafka_consumergroup_lag_sum)'),
      queryValue('min((probe_ssl_earliest_cert_expiry - time()) / 86400)'),
    ]);

    // Service statuses
    const serviceJobs = [
      { name: 'FreeRADIUS', query: 'up{job="freeradius"}' },
      { name: 'MariaDB', query: 'up{job="mariadb-galera"}' },
      { name: 'Redis', query: 'up{job="redis"}' },
      { name: 'Kafka', query: 'up{job="kafka"}' },
      { name: 'Policy Engine', query: 'up{job="policy-engine"}' },
      { name: 'Posture', query: 'up{job="posture-engine"}' },
      { name: 'Profiler', query: 'up{job="profiler"}' },
      { name: 'Admin UI', query: 'up{job="nginx"}' },
    ];

    const serviceStatuses = await Promise.all(
      serviceJobs.map(async (svc) => ({
        name: svc.name,
        up: await queryValue(svc.query),
      }))
    );

    // Active alerts count
    let alertCount = null;
    try {
      const alertResp = await fetch(`${PROMETHEUS_BASE}/api/v1/alerts`);
      const alertData = await alertResp.json();
      if (alertData.status === 'success') {
        alertCount = alertData.data.alerts.filter((a) => a.state === 'firing').length;
      }
    } catch { /* ignore */ }

    setMetrics({
      services: serviceStatuses,
      cpuPercent: cpu !== null ? cpu.toFixed(1) : null,
      memPercent: mem !== null ? mem.toFixed(1) : null,
      diskPercent: disk !== null ? disk.toFixed(1) : null,
      authPerSec: authRate !== null ? authRate.toFixed(1) : null,
      rejectRate: rejectPct !== null ? rejectPct.toFixed(1) : null,
      connectedEndpoints: endpoints !== null ? Math.round(endpoints) : null,
      galeraClusterSize: galeraSize !== null ? Math.round(galeraSize) : null,
      galeraReady: galeraRdy,
      kafkaLag: kafkaLagVal !== null ? Math.round(kafkaLagVal) : null,
      activeAlerts: alertCount,
      certDaysLeft: certDays !== null ? Math.round(certDays) : null,
    });
    setLastUpdate(new Date());
  }, []);

  useEffect(() => {
    fetchMetrics();
    const timer = setInterval(fetchMetrics, REFRESH_INTERVAL);
    return () => clearInterval(timer);
  }, [fetchMetrics]);

  const getColor = (val, warn, crit) => {
    if (val === null) return '#6b7280';
    if (val >= crit) return '#ef4444';
    if (val >= warn) return '#f59e0b';
    return '#22c55e';
  };

  return (
    <div style={{ fontFamily: "'Inter', -apple-system, sans-serif" }}>
      {/* Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '16px',
        }}
      >
        <h2 style={{ fontSize: '18px', fontWeight: 600, margin: 0, color: '#111827' }}>
          System Monitoring
        </h2>
        <div style={{ fontSize: '12px', color: '#9ca3af' }}>
          {lastUpdate ? `Updated ${lastUpdate.toLocaleTimeString()}` : 'Loading...'}
          <a
            href="https://10.10.10.173:3000"
            target="_blank"
            rel="noopener noreferrer"
            style={{ marginLeft: '12px', color: '#3b82f6', textDecoration: 'none' }}
          >
            Open Grafana →
          </a>
        </div>
      </div>

      {/* Service Status */}
      <div
        style={{
          background: '#fff',
          borderRadius: '12px',
          padding: '16px 20px',
          boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
          border: '1px solid #e5e7eb',
          marginBottom: '16px',
        }}
      >
        <div style={{ fontSize: '13px', color: '#6b7280', fontWeight: 500, marginBottom: '4px' }}>
          Service Health — {metrics.services.filter((s) => s.up === 1).length}/{metrics.services.length} UP
        </div>
        <ServiceStatusGrid services={metrics.services} />
      </div>

      {/* Metric Cards */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
        <MetricCard
          title="CPU"
          value={metrics.cpuPercent}
          unit="%"
          color={getColor(parseFloat(metrics.cpuPercent), 60, 85)}
          icon="⚡"
        />
        <MetricCard
          title="Memory"
          value={metrics.memPercent}
          unit="%"
          color={getColor(parseFloat(metrics.memPercent), 60, 85)}
          icon="🧠"
        />
        <MetricCard
          title="Disk"
          value={metrics.diskPercent}
          unit="%"
          color={getColor(parseFloat(metrics.diskPercent), 70, 90)}
          icon="💾"
        />
        <MetricCard
          title="Auth Rate"
          value={metrics.authPerSec}
          unit="req/s"
          color="#3b82f6"
          icon="🔐"
        />
        <MetricCard
          title="Reject Rate"
          value={metrics.rejectRate}
          unit="%"
          color={getColor(parseFloat(metrics.rejectRate), 15, 30)}
          icon="🚫"
        />
        <MetricCard
          title="Endpoints"
          value={metrics.connectedEndpoints}
          color="#8b5cf6"
          icon="📱"
        />
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px' }}>
        <MetricCard
          title="Galera Cluster"
          value={`${metrics.galeraClusterSize ?? '—'}/3`}
          color={metrics.galeraClusterSize === 3 ? '#22c55e' : '#ef4444'}
          icon="🗄️"
          subtitle={metrics.galeraReady === 1 ? 'Ready' : 'Not Ready'}
        />
        <MetricCard
          title="Kafka Lag"
          value={metrics.kafkaLag}
          unit="msgs"
          color={getColor(metrics.kafkaLag, 5000, 20000)}
          icon="📨"
        />
        <MetricCard
          title="Active Alerts"
          value={metrics.activeAlerts}
          color={metrics.activeAlerts > 0 ? '#ef4444' : '#22c55e'}
          icon="🔔"
        />
        <MetricCard
          title="Cert Expiry"
          value={metrics.certDaysLeft}
          unit="days"
          color={getColor(
            metrics.certDaysLeft !== null ? 100 - metrics.certDaysLeft : 0,
            70,
            93
          )}
          icon="📜"
        />
      </div>
    </div>
  );
}
