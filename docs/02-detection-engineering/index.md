---
title: Detection Engineering
description: "Query references and repository examples for KQL, CQL, and Splunk."
permalink: /detection-engineering/
---

<header class="page-header">
  <span class="eyebrow">Query library</span>
  <h1>Detection Engineering</h1>
  <p class="lead">Turn threat hypotheses into versioned, testable analytics. Start with a behavior, identify telemetry, test expected results, and document the operational response.</p>
</header>

<section class="filter-region" data-filter-region data-filter-label="Filter detection query formats">
<div class="tag-filter" data-filter-controls></div>
<p class="filter-status" data-filter-status aria-live="polite"></p>
<div class="card-grid card-grid--three">
  <article class="card card--featured" data-filter-item data-tags="Microsoft,Queries,KQL">
    <div class="card__meta"><span class="category-chip">Microsoft</span><span class="category-chip">Queries</span></div>
    <h3>Kusto Query Language</h3>
    <p>Microsoft language reference plus Sentinel query examples stored in this repository.</p>
    <a class="button" href="{{ '/detection-engineering/kql/' | relative_url }}">Explore KQL</a>
  </article>
  <article class="card" data-filter-item data-tags="CrowdStrike,Queries,CQL">
    <div class="card__meta"><span class="category-chip">CrowdStrike</span><span class="category-chip">Queries</span></div>
    <h3>CrowdStrike Query Language</h3>
    <p>LogScale syntax reference with practical validation considerations.</p>
    <a class="button" href="{{ '/detection-engineering/cql/' | relative_url }}">Explore CQL</a>
  </article>
  <article class="card" data-filter-item data-tags="Splunk,Queries,SPL">
    <div class="card__meta"><span class="category-chip">Splunk</span><span class="category-chip">Queries</span></div>
    <h3>Search Processing Language</h3>
    <p>Splunk search reference and guidance for production-ready analytics.</p>
    <a class="button" href="{{ '/detection-engineering/splunk/' | relative_url }}">Explore SPL</a>
  </article>
  <article class="card" data-filter-item data-tags="Cross-platform,Detections,AI security,MITRE ATLAS">
    <div class="card__meta"><span class="category-chip">Cross-platform</span><span class="category-chip">Detections</span></div>
    <h3>Elastic AI security detection rules</h3>
    <p>Elastic's Nov 2026 collection covers coding agents, MCP servers, AI platforms, prompt credential leakage, jailbreak activity, and stolen model keys with 143 SIEM rules mapped to MITRE ATLAS and ATT&amp;CK. Source is published in the <a href="https://github.com/elastic/detection-rules">detection-rules repository</a>. The announcement applies to Elastic Cloud Serverless; hosted and self-managed 9.6 availability was expected in early December. Enable only rules supported by local telemetry, then test and tune them.</p>
    <a class="button" href="https://www.elastic.co/security-labs/blog/ai-security-detection-rules-coding-agents-mcp">Visit source</a>
  </article>
</div>
</section>

<div class="callout">
  <span class="callout__mark" aria-hidden="true">i</span>
  <p>Use <a href="https://attack.mitre.org/">MITRE ATT&amp;CK</a> as a vocabulary for behaviors and coverage, not as a substitute for testing against local data.</p>
</div>
