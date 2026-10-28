---
title: PHP2Shell — the runtime
description: "Active worldwide-impact advisory for CVE-2026-109618 and CVE-2026-109619 in the PHP runtime."
permalink: /advisories/php2shell/
---

<header class="page-header">
  <span class="eyebrow">Worldwide-impact advisory</span>
  <h1>PHP2Shell — the runtime</h1>
  <p class="lead">Two critical remote-code-execution vulnerabilities are in the PHP engine. Patch the runtime serving traffic—not only the CMS, application, or plugin.</p>
  <div class="card__meta"><span class="category-chip">Active</span><span class="category-chip">Oct 2026</span><span class="category-chip">Runtime patch required</span></div>
  <div class="hero__actions">
    <a class="button" href="https://amcamillo.github.io/thinkinfosec-hub/Research/php2shell/">Read the full hub briefing</a>
    <a class="button button--secondary" href="https://www.php.net/archive/2026.php#2026-10-21-5">Read the PHP advisory</a>
  </div>
</header>

<div class="callout">
  <span class="callout__mark" aria-hidden="true">!</span>
  <p><strong>Why this is here:</strong> PHP2Shell is a rare worldwide-impact event involving unauthenticated code execution in a widely deployed runtime. This page is an operational summary, not a CVE feed, and intentionally excludes exploit steps, payloads, and reproduction procedures. <a href="https://amcamillo.github.io/thinkinfosec-hub/Research/php2shell/">ThinkInfoSec briefing</a></p>
</div>

<div class="section-heading">
  <h2><span class="section-kicker">Update · 28 October 2026</span>Exploitation confirmed by government sources</h2>
  <p>Review state: Active. Patch immediately and investigate suspected compromise.</p>
</div>

<div class="resource-list">
  <article class="resource-row">
    <h3>CISA adds both vulnerabilities to KEV</h3>
    <p>On 26 October, CISA added CVE-2026-109618 and CVE-2026-109619 to its Known Exploited Vulnerabilities Catalog and <a href="https://www.cisa.gov/news-events/alerts/2026/10/26/cisa-adds-two-known-exploited-vulnerabilities-catalog">announced the additions</a>. Its <a href="https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching">PHP alert, last revised 26 October</a>, records the KEV additions and its 23 October update adding a SIGMA detection rule. The fixed versions remain PHP 8.5.12, 8.4.27, 8.3.36, and 8.2.35.</p>
  </article>
  <article class="resource-row">
    <h3>Government guidance and known limits</h3>
    <p>Federal civilian agencies received a 29 October remediation deadline. The catalog entries do not identify victims, and the extent of successful attacks remains unclear, according to <a href="https://www.nextgov.com/cybersecurity/2026/10/cisa-gives-federal-agencies-until-thursday-address-exploited-php-flaws/416838/">Nextgov/FCW</a>. The <a href="https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php">UK NCSC guidance</a> calls for immediate action, while New Zealand's NCSC said it was aware of reports of active exploitation, as <a href="https://www.reseller.co.nz/article/4238792/ncsc-issues-alert-over-two-critical-php-flaws.html">reported by Reseller News</a>.</p>
  </article>
</div>

<div class="section-heading">
  <h2><span class="section-kicker">Scope</span>Inventory the PHP process</h2>
  <p>The application version is not the right inventory line for an engine vulnerability.</p>
</div>

<div class="card-grid card-grid--two">
  <article class="card card--featured">
    <div class="card__meta"><span class="category-chip">CVE-2026-109618</span><span class="category-chip">CVE-2026-109619</span></div>
    <h3>Two critical engine vulnerabilities</h3>
    <p>Both issues can allow unauthenticated remote code execution in PHP installations serving web requests. The PHP project scores each advisory CVSS v4.0 9.2; the leaked 10.0 figure was not the published score.</p>
    <div>
      <a class="text-link" href="https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w">GHSA-w8hw-w9fx-j79w</a><br>
      <a class="text-link" href="https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp">GHSA-6wmf-4rv5-p3rp</a><br>
      <a class="text-link" href="https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/">PHP Foundation disclosure account</a>
    </div>
  </article>
  <article class="card">
    <div class="card__meta"><span class="category-chip">Server APIs</span></div>
    <h3>mod_php is the highest demonstrated risk</h3>
    <p>PHP-FPM, Apache with mod_php, php-cgi, FrankenPHP, and LiteSpeed are in patch scope. The PHP project identifies mod_php as highest risk; PHP-FPM remains in scope and must be patched.</p>
    <div>
      <a class="text-link" href="https://www.php.net/archive/2026.php#2026-10-21-5">PHP project scope</a><br>
      <a class="text-link" href="https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching">CISA alert</a>
    </div>
  </article>
</div>

<div class="section-heading">
  <h2><span class="section-kicker">Stage 1 · This week</span>Patch, restart, and verify</h2>
  <p>Close the ticket on the runtime build that is actually serving requests.</p>
</div>

<div class="resource-list">
  <article class="resource-row">
    <h3>1. Inventory every web-serving PHP runtime</h3>
    <p>Include third-party products, appliances, containers, and software that embeds PHP; its presence may not be obvious from the application inventory.</p>
    <div>
      <a class="text-link" href="https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching">CISA inventory guidance</a><br>
      <a class="text-link" href="https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619">Cyber Centre AL26-026</a>
    </div>
  </article>
  <article class="resource-row">
    <h3>2. Move supported branches to fixed releases</h3>
    <p>Update to PHP 8.5.12, 8.4.27, 8.3.36, or 8.2.35, or use a vendor package containing the fixes. Restart every PHP worker, then verify the runtime build serving production traffic.</p>
    <div>
      <a class="text-link" href="https://www.php.net/archive/2026.php#2026-10-21-5">PHP releases and remediation</a><br>
      <a class="text-link" href="https://amcamillo.github.io/thinkinfosec-hub/Research/php2shell/">ThinkInfoSec operational briefing</a>
    </div>
  </article>
  <article class="resource-row">
    <h3>3. Take unpatchable internet-facing systems offline</h3>
    <p>If an update cannot be applied immediately—especially for PHP 8.1 and earlier—CISA advises taking PHP-based systems offline until they can be patched or updated. The Cyber Centre recommends isolation from public networks where immediate remediation is not feasible.</p>
    <div>
      <a class="text-link" href="https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching">CISA actions</a><br>
      <a class="text-link" href="https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619">Cyber Centre actions</a>
    </div>
  </article>
  <article class="resource-row">
    <h3>4. Do not close on an application update</h3>
    <p>Updating a CMS, application, or plugin alone does not fix these engine vulnerabilities. A WAF or configuration change can reduce exposure to some paths, but only the runtime update is a complete fix.</p>
    <div>
      <a class="text-link" href="https://blog.cloudflare.com/php-vulnerabilities-waf-protection/">Cloudflare vendor bulletin</a><br>
      <a class="text-link" href="https://vercel.com/kb/bulletin/php2shell-security-bulletin">Vercel vendor bulletin</a>
    </div>
  </article>
</div>

<div class="section-heading">
  <h2><span class="section-kicker">Detection</span>Hunt at a high level</h2>
  <p>Use these signals to prioritize investigation while the estate is mixed; they are not proof of compromise and do not replace patching.</p>
</div>

<div class="card-grid card-grid--two">
  <article class="card">
    <div class="card__meta"><span class="category-chip">Process and network</span></div>
    <h3>Unexpected PHP or web-server behavior</h3>
    <p>Investigate PHP workers launching shells or downloading tools, and unexpected processes, commands, files, accounts, or outbound connections associated with PHP or web-server services.</p>
    <div>
      <a class="text-link" href="https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching">CISA detection guidance</a><br>
      <a class="text-link" href="https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619">Cyber Centre detection guidance</a>
    </div>
  </article>
  <article class="card">
    <div class="card__meta"><span class="category-chip">Application and worker</span></div>
    <h3>Request errors and worker churn</h3>
    <p>Wiz recommends investigating unusual multipart requests followed by memory-limit errors or repeated HTTP 500 responses, unexpectedly large or malformed PHPSESSID cookies, and unexplained worker churn.</p>
    <a class="text-link" href="https://www.wiz.io/blog/php2shell-php-rce">Wiz researcher write-up</a>
  </article>
</div>

<div class="callout">
  <span class="callout__mark" aria-hidden="true">i</span>
  <p><strong>Keep the identifiers separate:</strong> PHP2Shell here means CVE-2026-109618 and CVE-2026-109619, not the 2012 PHP-CGI query-string issue CVE-2012-1823. CVE-2026-115560 concerns session upload progress and is an adjacent follow-on, not PHP2Shell; the 21 October releases do not close it. <a href="https://amcamillo.github.io/thinkinfosec-hub/Research/php2shell/">ThinkInfoSec briefing</a> · <a href="https://www.php.net/archive/2026.php">PHP News Archive — 2026</a></p>
</div>

<div class="section-heading">
  <h2><span class="section-kicker">Sources</span>Briefing and references</h2>
  <p>Original sources were read on 26 October 2026; update sources were read on 28 October 2026. Project and national sources are listed before labelled researcher and vendor material.</p>
</div>

<div class="resource-list">
  <article class="resource-row">
    <h3>ThinkInfoSec briefing</h3>
    <p>Independent synthesis, collection window, source boundaries, and the complete source list for this advisory.</p>
    <a class="text-link" href="https://amcamillo.github.io/thinkinfosec-hub/Research/php2shell/">PHP2Shell and the runtime</a>
  </article>
  <article class="resource-row">
    <h3>PHP project</h3>
    <p>Official release advisory, two GitHub security advisories, and the PHP Foundation disclosure account.</p>
    <div>
      <a class="text-link" href="https://www.php.net/archive/2026.php#2026-10-21-5">PHP security advisory and releases</a><br>
      <a class="text-link" href="https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w">GHSA-w8hw-w9fx-j79w</a><br>
      <a class="text-link" href="https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp">GHSA-6wmf-4rv5-p3rp</a><br>
      <a class="text-link" href="https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/">PHP Foundation post</a>
    </div>
  </article>
  <article class="resource-row">
    <h3>National and coordination advisories</h3>
    <p>Operational guidance from CISA, the Canadian Centre for Cyber Security, and CERT/CC.</p>
    <div>
      <a class="text-link" href="https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching">CISA alert</a><br>
      <a class="text-link" href="https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619">Cyber Centre AL26-026</a><br>
      <a class="text-link" href="https://www.kb.cert.org/vuls/id/763488">CERT/CC VU#763488</a>
    </div>
  </article>
  <article class="resource-row">
    <h3>Researcher and vendor bulletins</h3>
    <p>Labelled secondary material on demonstrated impact, investigation signals, and edge controls.</p>
    <div>
      <a class="text-link" href="https://www.wiz.io/blog/php2shell-php-rce">Wiz Research</a><br>
      <a class="text-link" href="https://blog.cloudflare.com/php-vulnerabilities-waf-protection/">Cloudflare</a><br>
      <a class="text-link" href="https://vercel.com/kb/bulletin/php2shell-security-bulletin">Vercel</a>
    </div>
  </article>
</div>
