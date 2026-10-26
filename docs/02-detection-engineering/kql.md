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

<div class="card-grid card-grid--two">
  <article class="card">
    <div class="card__meta"><span class="category-chip">Reference</span></div>
    <h3>Microsoft KQL reference</h3>
    <p>Official Kusto Query Language overview and query documentation.</p>
    <a class="button" href="https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric">Visit source</a>
  </article>
  <article class="card">
    <div class="card__meta"><span class="category-chip">Repository</span></div>
    <h3>KQL examples</h3>
    <p>Browse the Microsoft Sentinel KQL directory in this repository.</p>
    <a class="button" href="https://github.com/amcamillo/Cybersecurity_Tools/tree/main/Vendors/Microsoft/Sentinel/KQL">Browse examples</a>
  </article>
  <article class="card">
    <div class="card__meta"><span class="category-chip">Example</span></div>
    <h3>MDEASM high vulnerabilities</h3>
    <p>A repository query example for MDEASM high-vulnerability results.</p>
    <a class="button" href="https://github.com/amcamillo/Cybersecurity_Tools/blob/main/Vendors/Microsoft/Sentinel/KQL/MDEASM_HighVulnerabilities">View example</a>
  </article>
  <article class="card">
    <div class="card__meta"><span class="category-chip">Example</span></div>
    <h3>Local-time conversion</h3>
    <p>A repository example for working with local-time conversion.</p>
    <a class="button" href="https://github.com/amcamillo/Cybersecurity_Tools/blob/main/Vendors/Microsoft/Sentinel/KQL/localtime">View example</a>
  </article>
</div>

<div class="callout">
  <span class="callout__mark" aria-hidden="true">i</span>
  <p>Confirm schemas, time windows, joins, and expected result volume against the target Sentinel or Defender environment before promoting a query to a detection.</p>
</div>
