/* ================================================================
   SHADOWPRINT DASHBOARD — Application Logic
   ================================================================ */

(function () {
    'use strict';

    // ── State ──────────────────────────────────────────────────
    let dashboardData = null;

    // ── DOM Elements ───────────────────────────────────────────
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    // ── Initialize ─────────────────────────────────────────────
    async function init() {
        createParticles();
        setupNavScroll();
        setupNavLinks();

        try {
            const resp = await fetch('dashboard_data.json');
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            dashboardData = await resp.json();

            setStatus('success', 'Data Loaded');
            renderAll();
        } catch (err) {
            console.error('Failed to load dashboard data:', err);
            setStatus('error', 'Data Error');
            renderFallback();
        }
    }

    // ── Particles Background ───────────────────────────────────
    function createParticles() {
        const container = $('#bgParticles');
        const count = 40;

        for (let i = 0; i < count; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.style.left = `${Math.random() * 100}%`;
            particle.style.animationDuration = `${12 + Math.random() * 20}s`;
            particle.style.animationDelay = `${Math.random() * 10}s`;
            particle.style.width = `${1 + Math.random() * 2}px`;
            particle.style.height = particle.style.width;

            const colors = ['#06b6d4', '#3b82f6', '#8b5cf6', '#10b981'];
            particle.style.background = colors[Math.floor(Math.random() * colors.length)];

            container.appendChild(particle);
        }
    }

    // ── Nav Scroll Effect ──────────────────────────────────────
    function setupNavScroll() {
        const nav = $('#topNav');
        window.addEventListener('scroll', () => {
            nav.classList.toggle('scrolled', window.scrollY > 20);
        });
    }

    // ── Nav Links ──────────────────────────────────────────────
    function setupNavLinks() {
        $$('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                $$('.nav-link').forEach(l => l.classList.remove('active'));
                link.classList.add('active');
            });
        });

        // Highlight on scroll
        const sections = ['overview', 'demo-explorer', 'audits', 'scorecard', 'triage', 'engines'];
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    $$('.nav-link').forEach(l => l.classList.remove('active'));
                    const link = $(`.nav-link[data-section="${entry.target.id}"]`);
                    if (link) link.classList.add('active');
                }
            });
        }, { threshold: 0.2, rootMargin: '-60px 0px 0px 0px' });

        sections.forEach(id => {
            const el = $(`#${id}`);
            if (el) observer.observe(el);
        });
    }

    // ── Status Indicator ───────────────────────────────────────
    function setStatus(type, text) {
        const dot = $('#statusDot');
        const label = $('#statusText');
        dot.className = `status-dot ${type}`;
        label.textContent = text;
    }

    // ── Render All Sections ────────────────────────────────────
    function renderAll() {
        renderHeroStats();
        renderOverview();
        renderDemoExplorer();
        renderAudits();
        renderScorecard();
        renderTriage();
        renderEngines();

        if (dashboardData.generated_at) {
            $('#generatedAt').textContent = `Report Generated: ${dashboardData.generated_at}`;
        }
    }

    // ── Render: Demo MCP Explorer & Console Simulator ──────────
    let selectedMcpId = 'vulnerable_runner';

    function renderDemoExplorer() {
        const selectorGrid = $('#mcpSelectorGrid');
        const mcps = dashboardData.demo_mcp_servers || [];
        if (!mcps.length) return;

        // Render Selector Cards
        selectorGrid.innerHTML = mcps.map(mcp => {
            const isActive = mcp.id === selectedMcpId;
            return `
                <div class="mcp-selector-card ${isActive ? 'active' : ''}" data-id="${mcp.id}" id="mcp-card-${mcp.id}">
                    <div class="mcp-card-top">
                        <div class="mcp-card-icon-name">
                            <span>${mcp.icon || '📦'}</span>
                            <span>${escapeHtml(mcp.name)}</span>
                        </div>
                        <span class="mcp-card-badge ${mcp.verdict_class}">${mcp.verdict}</span>
                    </div>
                    <div class="mcp-card-category">${escapeHtml(mcp.category_badge)}</div>
                    <div class="mcp-card-tagline" title="${escapeHtml(mcp.tagline)}">${escapeHtml(mcp.tagline)}</div>
                </div>
            `;
        }).join('');

        // Card Click Handlers
        $$('.mcp-selector-card').forEach(card => {
            card.addEventListener('click', () => {
                selectedMcpId = card.dataset.id;
                $$('.mcp-selector-card').forEach(c => c.classList.remove('active'));
                card.classList.add('active');
                const mcp = mcps.find(m => m.id === selectedMcpId);
                if (mcp) renderActiveMcp(mcp);
            });
        });

        // Initial Active MCP
        const initialMcp = mcps.find(m => m.id === selectedMcpId) || mcps[0];
        if (initialMcp) renderActiveMcp(initialMcp);
    }

    function renderActiveMcp(mcp) {
        const container = $('#mcpViewerContainer');

        const plantedItems = (mcp.demo_highlights || []).map(h => `
            <div class="planted-vector-item">
                <div class="planted-vector-head">
                    <span class="planted-vector-name">${escapeHtml(h.title)}</span>
                    <span class="finding-severity-badge ${h.severity}">${h.severity.toUpperCase()}</span>
                </div>
                <div class="planted-vector-desc">${escapeHtml(h.desc)}</div>
            </div>
        `).join('');

        container.innerHTML = `
            <!-- Left Column: Terminal Console Window -->
            <div class="terminal-window">
                <div class="terminal-header">
                    <div class="terminal-dots">
                        <span class="terminal-dot red"></span>
                        <span class="terminal-dot yellow"></span>
                        <span class="terminal-dot green"></span>
                    </div>
                    <div class="terminal-title">shadowprint-cli — ${escapeHtml(mcp.id)}</div>
                    <button class="copy-btn" id="copyCliBtn" data-cmd="${escapeHtml(mcp.cli_command)}" title="Copy CLI command to clipboard">
                        <span>📋</span> <span id="copyBtnText">Copy Command</span>
                    </button>
                </div>
                <div class="terminal-command-bar">
                    <span class="terminal-prompt-user">auditor@shadowprint:~$</span>
                    <span>${escapeHtml(mcp.cli_command)}</span>
                </div>
                <div class="terminal-body" id="terminalOutput">${escapeHtml(mcp.console_output || '')}</div>
            </div>

            <!-- Right Column: MCP Feature Profile & Vectors -->
            <div class="mcp-profile-wrap">
                <div class="mcp-info-card">
                    <div class="mcp-info-header">
                        <div>
                            <div class="mcp-info-title">${mcp.icon || '🛡️'} ${escapeHtml(mcp.name)}</div>
                            <span class="mcp-card-category">${escapeHtml(mcp.category_badge)}</span>
                        </div>
                        <span class="mcp-card-badge ${mcp.verdict_class}">${mcp.verdict}</span>
                    </div>

                    <div class="mcp-info-meta">
                        <div class="mcp-meta-row"><span>Target Engine:</span> <strong>${escapeHtml(mcp.target_engine)}</strong></div>
                        <div class="mcp-meta-row"><span>Builder / Owner:</span> <strong>${escapeHtml(mcp.owner)}</strong></div>
                        <div class="mcp-meta-row"><span>Fixture Path:</span> <code>${escapeHtml(mcp.fixture_path)}</code></div>
                    </div>

                    <div class="mcp-info-desc">${escapeHtml(mcp.description)}</div>

                    <div class="mcp-planted-title">Planted Vectors &amp; Engine Detection Showcase ("Shows This &amp; This")</div>
                    <div class="planted-vectors-list">
                        ${plantedItems}
                    </div>

                    <a href="#audits" class="jump-audit-btn" data-target="${mcp.id}">
                        🔍 View SARIF Findings in Audit Tab →
                    </a>
                </div>
            </div>
        `;

        // Copy button handler
        const copyBtn = $('#copyCliBtn');
        if (copyBtn) {
            copyBtn.addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(mcp.cli_command);
                    copyBtn.classList.add('copied');
                    $('#copyBtnText').textContent = 'Copied!';
                    setTimeout(() => {
                        copyBtn.classList.remove('copied');
                        $('#copyBtnText').textContent = 'Copy Command';
                    }, 2000);
                } catch (e) {
                    const ta = document.createElement('textarea');
                    ta.value = mcp.cli_command;
                    document.body.appendChild(ta);
                    ta.select();
                    document.execCommand('copy');
                    document.body.removeChild(ta);
                    copyBtn.classList.add('copied');
                    $('#copyBtnText').textContent = 'Copied!';
                    setTimeout(() => {
                        copyBtn.classList.remove('copied');
                        $('#copyBtnText').textContent = 'Copy Command';
                    }, 2000);
                }
            });
        }

        // Jump to audit tab handler
        const jumpBtn = $('.jump-audit-btn');
        if (jumpBtn) {
            jumpBtn.addEventListener('click', (e) => {
                const targetId = jumpBtn.dataset.target;
                const tab = $(`#audit-tab-${targetId}`);
                if (tab) {
                    tab.click();
                }
            });
        }
    }

    // ── Render: Hero Stats ─────────────────────────────────────
    function renderHeroStats() {
        const container = $('#heroStats');
        const reports = dashboardData.audit_reports || {};
        const scorecard = dashboardData.scorecard || {};

        const totalFindings = Object.values(reports).reduce((s, r) => s + (r.total_findings || 0), 0);
        const totalServers = Object.keys(reports).length;
        const passedServers = Object.values(reports).filter(r => r.verdict === 'PASSED').length;
        const failedServers = Object.values(reports).filter(r => r.verdict === 'FAILED').length;

        const stats = [
            { value: totalServers, label: 'Servers Audited', cls: 'neutral' },
            { value: passedServers, label: 'Passed', cls: 'pass' },
            { value: failedServers, label: 'Failed', cls: 'fail' },
            { value: totalFindings, label: 'Total Findings', cls: failedServers > 0 ? 'fail' : 'pass' },
            { value: scorecard.recall_rate || '—', label: 'Benchmark Recall', cls: 'pass' },
        ];

        container.innerHTML = stats.map(s => `
            <div class="hero-stat">
                <div class="hero-stat-value ${s.cls}">${s.value}</div>
                <div class="hero-stat-label">${s.label}</div>
            </div>
        `).join('');
    }

    // ── Render: Overview Cards ──────────────────────────────────
    function renderOverview() {
        const container = $('#overviewGrid');
        const reports = dashboardData.audit_reports || {};

        const cards = Object.entries(reports).map(([name, report], i) => {
            const severity = report.severity_counts || {};
            const verdictClass = (report.verdict || 'PASSED').toLowerCase();

            return `
                <div class="overview-card ${verdictClass}" style="animation-delay: ${i * 0.1}s">
                    <div class="card-header">
                        <span class="card-server-name">${name}</span>
                        <span class="card-verdict ${verdictClass}">${report.verdict}</span>
                    </div>
                    <div class="card-severity-bars">
                        <div class="severity-bar critical">C: ${severity.critical || 0}</div>
                        <div class="severity-bar high">H: ${severity.high || 0}</div>
                        <div class="severity-bar medium">M: ${severity.medium || 0}</div>
                        <div class="severity-bar low">L: ${severity.low || 0}</div>
                    </div>
                    <div class="card-findings-total">
                        Total Findings: <strong>${report.total_findings || 0}</strong>
                    </div>
                </div>
            `;
        });

        container.innerHTML = cards.join('');
    }

    // ── Render: Audit Reports ──────────────────────────────────
    function renderAudits() {
        const tabsContainer = $('#auditTabs');
        const contentContainer = $('#auditContent');
        const reports = dashboardData.audit_reports || {};
        const names = Object.keys(reports);

        // Tabs
        tabsContainer.innerHTML = names.map((name, i) => `
            <button class="audit-tab ${i === 0 ? 'active' : ''}" data-target="${name}" id="audit-tab-${name}">${name}</button>
        `).join('');

        // Content
        contentContainer.innerHTML = names.map((name, i) => {
            const report = reports[name];
            const findings = report.findings || [];

            if (findings.length === 0) {
                return `
                    <div class="audit-panel ${i === 0 ? 'active' : ''}" id="audit-panel-${name}">
                        <div class="no-findings-msg">
                            <span class="icon">✅</span>
                            Zero findings detected — Server passed all security gates
                        </div>
                    </div>
                `;
            }

            const findingsHTML = findings.map(f => `
                <div class="finding-card ${f.severity}">
                    <div class="finding-header">
                        <span class="finding-severity-badge ${f.severity}">${f.severity.toUpperCase()}</span>
                        <span class="finding-rule-name">${f.ruleName}</span>
                        <span class="finding-rule-id">${f.ruleId}</span>
                    </div>
                    <div class="finding-meta">
                        <span><span class="label">Engine:</span> ${f.engine}</span>
                        <span><span class="label">Tool:</span> ${f.tool}</span>
                        <span><span class="label">File:</span> ${f.location?.file || '—'}:${f.location?.line || '—'}</span>
                        <span><span class="label">Confidence:</span> ${f.confidence}</span>
                    </div>
                    <div class="finding-evidence">${escapeHtml(f.message)}</div>
                    ${f.remediation ? `<div class="finding-remediation">💡 ${escapeHtml(f.remediation)}</div>` : ''}
                </div>
            `).join('');

            return `
                <div class="audit-panel ${i === 0 ? 'active' : ''}" id="audit-panel-${name}">
                    <div class="findings-list">${findingsHTML}</div>
                </div>
            `;
        }).join('');

        // Tab click handler
        $$('.audit-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                $$('.audit-tab').forEach(t => t.classList.remove('active'));
                $$('.audit-panel').forEach(p => p.classList.remove('active'));
                tab.classList.add('active');
                const panel = $(`#audit-panel-${tab.dataset.target}`);
                if (panel) panel.classList.add('active');
            });
        });
    }

    // ── Render: Scorecard ──────────────────────────────────────
    function renderScorecard() {
        const summaryContainer = $('#scorecardSummary');
        const tableContainer = $('#scorecardTable');
        const sc = dashboardData.scorecard || {};

        // Summary stats
        summaryContainer.innerHTML = `
            <div class="scorecard-stat">
                <div class="scorecard-stat-value info">${sc.total_fixtures || 0}</div>
                <div class="scorecard-stat-label">Total Fixtures</div>
            </div>
            <div class="scorecard-stat">
                <div class="scorecard-stat-value success">${sc.passed || 0}</div>
                <div class="scorecard-stat-label">Passed</div>
            </div>
            <div class="scorecard-stat">
                <div class="scorecard-stat-value danger">${sc.failed || 0}</div>
                <div class="scorecard-stat-label">Failed</div>
            </div>
            <div class="scorecard-stat">
                <div class="scorecard-stat-value success">${sc.recall_rate || '—'}</div>
                <div class="scorecard-stat-label">Recall Rate</div>
            </div>
        `;

        // Table
        const results = sc.results || [];
        const rows = results.map(r => {
            const expClass = r.expected_outcome === 'PASS' ? 'pass' : 'fail';
            const actClass = r.actual_outcome === 'PASS' ? 'pass' : (r.actual_outcome === 'FAIL' ? 'fail' : '');
            const statusClass = r.passed ? 'pass' : 'fail';
            const statusText = r.passed ? '✔ PASS 100%' : '✖ FAILED';

            return `
                <tr>
                    <td><span class="fixture-name">${r.name}</span></td>
                    <td><span class="outcome-badge ${expClass}">${r.expected_outcome}</span></td>
                    <td><span class="outcome-badge ${actClass}">${r.actual_outcome}</span></td>
                    <td style="text-align: center; font-family: var(--font-mono); font-weight: 600;">${r.findings_count}</td>
                    <td><span class="scorecard-status ${statusClass}">${statusText}</span></td>
                    <td style="color: var(--text-secondary); font-size: 0.78rem;">${r.details}</td>
                </tr>
            `;
        }).join('');

        tableContainer.innerHTML = `
            <table class="scorecard-table">
                <thead>
                    <tr>
                        <th>Fixture</th>
                        <th>Expected</th>
                        <th>Actual</th>
                        <th>Findings</th>
                        <th>Status</th>
                        <th>Diagnostic Details</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        `;
    }

    // ── Render: Graph Triage ────────────────────────────────────
    function renderTriage() {
        const container = $('#triageGrid');
        const triageData = dashboardData.graph_triage || {};

        const cards = Object.entries(triageData).map(([server, d]) => {
            const isApprove = d.action && d.action.includes('APPROVE');
            const actionClass = isApprove ? 'approve' : 'block';
            const actionLabel = d.action || 'UNKNOWN';
            const riskColor = d.overall_risk === 'LOW' ? 'safe' : (d.overall_risk === 'CRITICAL' ? 'danger' : 'neutral');
            const chainsColor = d.exploit_chains_found > 0 ? 'danger' : 'safe';
            const blastColor = d.max_blast_radius >= 8 ? 'danger' : (d.max_blast_radius >= 5 ? 'neutral' : 'safe');

            const steps = (d.reasoning_steps || []).map(s =>
                `<div class="reasoning-step">${escapeHtml(s)}</div>`
            ).join('');

            const hasRealWalkthrough = (d.attack_chain_walkthrough || []).some(w => !w.includes('isolated execution'));
            const walkthroughHTML = hasRealWalkthrough ? `
                <div class="triage-walkthrough">
                    <div class="triage-walkthrough-title">Multi-Hop Exploit Walkthrough</div>
                    ${d.attack_chain_walkthrough.map(w => `<div class="walkthrough-item">${escapeHtml(w)}</div>`).join('')}
                </div>
            ` : '';

            const remediationsHTML = (d.remediation_directives || []).length > 0 ? `
                <div style="margin-top: 12px;">
                    ${d.remediation_directives.map(r => `<div class="remediation-item">💡 ${escapeHtml(r)}</div>`).join('')}
                </div>
            ` : '';

            const patchHTML = d.patch_file ? `
                <div class="patch-badge">
                    <span>🩹 Patch:</span>
                    <code>${escapeHtml(d.patch_file)}</code>
                </div>
            ` : '';

            return `
                <div class="triage-card ${actionClass}">
                    <div class="triage-card-header">
                        <span class="triage-server">${server}</span>
                        <span class="triage-action-badge ${actionClass}">${actionLabel}</span>
                    </div>
                    <div class="triage-metrics">
                        <div class="triage-metric">
                            <div class="triage-metric-value ${riskColor}">${d.overall_risk || '—'}</div>
                            <div class="triage-metric-label">Risk Level</div>
                        </div>
                        <div class="triage-metric">
                            <div class="triage-metric-value ${chainsColor}">${d.exploit_chains_found ?? '—'}</div>
                            <div class="triage-metric-label">Exploit Chains</div>
                        </div>
                        <div class="triage-metric">
                            <div class="triage-metric-value ${blastColor}">${d.max_blast_radius ?? '—'}/10</div>
                            <div class="triage-metric-label">Blast Radius</div>
                        </div>
                    </div>
                    <div class="triage-summary">${escapeHtml(d.executive_summary || '')}</div>
                    ${walkthroughHTML}
                    <div class="triage-reasoning">
                        <div class="triage-reasoning-title">Autonomous Reasoning Steps</div>
                        ${steps}
                    </div>
                    ${remediationsHTML}
                    ${patchHTML}
                </div>
            `;
        });

        container.innerHTML = cards.join('');
    }

    // ── Render: Engines ────────────────────────────────────────
    function renderEngines() {
        const container = $('#enginesGrid');
        const engines = dashboardData.engines || [];

        const engineIcons = {
            'S0': '🔍', 'S1': '🛡️', 'S2': '⚡',
            'S3': '🔐', 'S4': '📊', 'S5': '🕸️',
        };

        container.innerHTML = engines.map(eng => `
            <div class="engine-card">
                <div class="engine-id">${engineIcons[eng.id] || '⚙️'} ENGINE ${eng.id}</div>
                <div class="engine-name">${eng.name}</div>
                <div class="engine-desc">${eng.description}</div>
            </div>
        `).join('');
    }

    // ── Fallback (if data fails to load) ───────────────────────
    function renderFallback() {
        $('#heroStats').innerHTML = `
            <div class="hero-stat">
                <div class="hero-stat-value fail">!</div>
                <div class="hero-stat-label">Data Error</div>
            </div>
        `;

        const msg = `
            <div class="no-findings-msg">
                <span class="icon">⚠️</span>
                Failed to load dashboard data.<br>
                Run <code style="background:rgba(255,255,255,0.1);padding:2px 8px;border-radius:4px;font-family:var(--font-mono)">
                python dashboard/generate_data.py</code> to generate data,<br>
                then serve with <code style="background:rgba(255,255,255,0.1);padding:2px 8px;border-radius:4px;font-family:var(--font-mono)">
                python -m http.server 8080 -d dashboard</code>
            </div>
        `;

        $('#overviewGrid').innerHTML = msg;
    }

    // ── Utilities ──────────────────────────────────────────────
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.appendChild(document.createTextNode(text || ''));
        return div.innerHTML;
    }

    // ── Boot ───────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', init);
})();
