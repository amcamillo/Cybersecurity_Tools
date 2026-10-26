---
title: Splunk SPL
description: "Splunk Search Processing Language reference and validation guidance."
permalink: /detection-engineering/splunk/
---

<header class="page-header">
  <span class="eyebrow">Detection Engineering · SPL</span>
  <h1>Splunk Search Processing Language</h1>
  <p class="lead">Use the linked search reference, then test searches against documented source types and normalized fields.</p>
</header>

<section class="filter-region" data-filter-region data-filter-label="Filter Splunk resources">
<div class="tag-filter" data-filter-controls></div>
<p class="filter-status" data-filter-status aria-live="polite"></p>
<div class="card-grid card-grid--two">
  <article class="card card--featured" data-filter-item data-tags="SPL,Reference,Splunk">
    <div class="card__meta"><span class="category-chip">Reference</span><span class="category-chip">Splunk</span></div>
    <h3>Splunk Search Reference</h3>
    <p>Search Processing Language documentation linked by this repository.</p>
    <a class="button" href="https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual">Visit source</a>
  </article>
  <div class="empty-state">
    <h3>Repository examples</h3>
    <p>No Splunk example set is currently linked from the repository catalog. Start with the reference and test against known data.</p>
    <a class="text-link" href="https://github.com/amcamillo/Cybersecurity_Tools">View repository</a>
  </div>
</div>
</section>

<div class="callout">
  <span class="callout__mark" aria-hidden="true">i</span>
  <p>Check time bounds, cardinality, acceleration assumptions, and false-positive handling before converting a search into a scheduled alert or correlation search.</p>
</div>
