---
title: KQL
description: "Kusto Query Language references and Microsoft Sentinel examples."
permalink: /detection-engineering/kql/
---

<header class="page-header">
  <span class="eyebrow">Detection Engineering · KQL</span>
  <h1>Kusto Query Language</h1>
  <p class="lead">Microsoft’s language reference and concrete Sentinel examples already maintained in this repository.</p>
</header>

<section class="filter-region" data-filter-region data-filter-label="Filter KQL resources">
<div class="tag-filter" data-filter-controls></div>
<p class="filter-status" data-filter-status aria-live="polite"></p>
<div class="card-grid card-grid--two">
  <article class="card card--featured" data-filter-item data-tags="KQL,Reference">
    <div class="card__meta"><span class="category-chip">Reference</span></div>
    <h3>Microsoft KQL reference</h3>
    <p>Official Kusto Query Language overview and query documentation.</p>
    <a class="button" href="https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric">Visit source</a>
  </article>
  <article class="card" data-filter-item data-tags="KQL,Repository">
    <div class="card__meta"><span class="category-chip">Repository</span></div>
    <h3>KQL examples</h3>
    <p>Browse the Microsoft Sentinel KQL directory in this repository.</p>
    <a class="button" href="https://github.com/amcamillo/Cybersecurity_Tools/tree/main/Vendors/Microsoft/Sentinel/KQL">Browse examples</a>
  </article>
  <article class="card" data-filter-item data-tags="KQL,Example,MDEASM">
    <div class="card__meta"><span class="category-chip">Example</span></div>
    <h3>MDEASM high vulnerabilities</h3>
    <p>A repository query example for MDEASM high-vulnerability results.</p>
    <a class="button" href="https://github.com/amcamillo/Cybersecurity_Tools/blob/main/Vendors/Microsoft/Sentinel/KQL/MDEASM_HighVulnerabilities">View example</a>
  </article>
  <article class="card" data-filter-item data-tags="KQL,Example,Local time">
    <div class="card__meta"><span class="category-chip">Example</span></div>
    <h3>Local-time conversion</h3>
    <p>A repository example for working with local-time conversion.</p>
    <a class="button" href="https://github.com/amcamillo/Cybersecurity_Tools/blob/main/Vendors/Microsoft/Sentinel/KQL/localtime">View example</a>
  </article>
  <article class="card" data-filter-item data-tags="KQL,Hunting,Microsoft">
    <div class="card__meta"><span class="category-chip">Hunting</span></div>
    <h3>LiteLLM supply-chain hunting queries</h3>
    <p>Microsoft Security Blog advanced hunting queries (Defender XDR) for the compromised LiteLLM 1.107.0 release; Microsoft frames them as investigation leads, not verdicts (Oct 2026).</p>
    <a class="button" href="https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/">Visit source</a>
  </article>
</div>
</section>

<div class="callout">
  <span class="callout__mark" aria-hidden="true">i</span>
  <p>Confirm schemas, time windows, joins, and expected result volume against the target Sentinel or Defender environment before promoting a query to a detection.</p>
</div>
