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

<div class="card-grid card-grid--three">
  <article class="card">
    <div class="card__meta"><span class="category-chip">Microsoft</span><span class="category-chip">Queries</span></div>
    <h3>Kusto Query Language</h3>
    <p>Microsoft language reference plus Sentinel query examples stored in this repository.</p>
    <a class="button" href="{{ '/detection-engineering/kql/' | relative_url }}">Explore KQL</a>
  </article>
  <article class="card">
    <div class="card__meta"><span class="category-chip">CrowdStrike</span><span class="category-chip">Queries</span></div>
    <h3>CrowdStrike Query Language</h3>
    <p>LogScale syntax reference with practical validation considerations.</p>
    <a class="button" href="{{ '/detection-engineering/cql/' | relative_url }}">Explore CQL</a>
  </article>
  <article class="card">
    <div class="card__meta"><span class="category-chip">Splunk</span><span class="category-chip">Queries</span></div>
    <h3>Search Processing Language</h3>
    <p>Splunk search reference and guidance for production-ready analytics.</p>
    <a class="button" href="{{ '/detection-engineering/splunk/' | relative_url }}">Explore SPL</a>
  </article>
</div>

<div class="callout">
  <span class="callout__mark" aria-hidden="true">i</span>
  <p>Use <a href="https://attack.mitre.org/">MITRE ATT&amp;CK</a> as a vocabulary for behaviors and coverage, not as a substitute for testing against local data.</p>
</div>
