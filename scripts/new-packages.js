#!/usr/bin/env node
// New-package check: every npm package a PR adds (package.json or npm lockfile) is looked up
// on the registry. Fails on names that don't exist (often invented by an AI assistant), on
// packages created less than MIN_PACKAGE_AGE_DAYS ago, and on versions published less than
// MIN_VERSION_AGE_DAYS ago. Warns (never fails) on direct dependencies with no repository
// field or a single maintainer. It does NOT catch a malicious release of an established
// package that is older than the limits, or a typosquat that has been around for a while.
//
//   node new-packages.js <base-sha> <findings.json>     (run in the repo, HEAD = PR head)
'use strict';
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');

const REGISTRY = (process.env.NPM_REGISTRY || 'https://registry.npmjs.org').replace(/\/$/, '');
const MIN_PACKAGE_AGE_DAYS = Number(process.env.MIN_PACKAGE_AGE_DAYS || 30);
const MIN_VERSION_AGE_DAYS = Number(process.env.MIN_VERSION_AGE_DAYS || 7);
const DAY = 24 * 3600 * 1000;
const DEP_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
const LOCKFILES = /(^|\/)(package-lock|npm-shrinkwrap)\.json$/;

const git = (...args) => execFileSync('git', args, { encoding: 'utf8', maxBuffer: 1 << 28 });
const readJson = (ref, path) => {
  try { return JSON.parse(git('show', `${ref}:${path}`)); } catch { return null; }
};

// name -> Set of versions ('' = any version, from a package.json range) the PR adds.
function addedPackages(base, head, files, read = readJson) {
  const added = new Map(); // name -> { versions:Set, path, direct }
  const add = (name, version, path, direct) => {
    const e = added.get(name) || { versions: new Set(), path, direct: false };
    if (version) e.versions.add(version);
    e.direct = e.direct || direct;
    added.set(name, e);
  };
  for (const path of files) {
    if (/(^|\/)package\.json$/.test(path)) {
      const names = (pj) => new Set(DEP_FIELDS.flatMap((f) => Object.keys((pj && pj[f]) || {})));
      const before = names(read(base, path));
      for (const n of names(read(head, path))) if (!before.has(n)) add(n, '', path, true);
    } else if (LOCKFILES.test(path)) {
      const entries = (lf) => Object.entries((lf && lf.packages) || {})
        .filter(([k, v]) => k && !v.link && (!v.resolved || v.resolved.startsWith(REGISTRY + '/')))
        .map(([k, v]) => [v.name || k.slice(k.lastIndexOf('node_modules/') + 13), v.version]);
      const before = new Set(entries(read(base, path)).map(([n, v]) => `${n}@${v}`));
      for (const [n, v] of entries(read(head, path))) if (!before.has(`${n}@${v}`)) add(n, v, path, false);
    }
  }
  return added;
}

// Findings and warnings for one package, from its full registry document (null = 404).
function judge(name, info, doc, now = Date.now()) {
  const f = [], w = [];
  const finding = (rule, message) => f.push({ tool: 'packages', rule, path: info.path, line: 1, message });
  if (!doc) {
    finding('package-not-found', `${name} does not exist on the registry: invented or misspelled name?`);
    return { f, w };
  }
  const days = (t) => Math.floor((now - Date.parse(t)) / DAY);
  const created = doc.time && doc.time.created;
  if (!created) finding('package-no-date', `${name}: the registry gives no creation date`);
  else if (days(created) < MIN_PACKAGE_AGE_DAYS)
    finding('package-too-new', `${name} was created ${days(created)} day(s) ago (minimum ${MIN_PACKAGE_AGE_DAYS})`);
  for (const v of info.versions) {
    const t = doc.time && doc.time[v];
    if (!t) finding('version-not-found', `${name}@${v} is not on the registry`);
    else if (days(t) < MIN_VERSION_AGE_DAYS)
      finding('version-too-new', `${name}@${v} was published ${days(t)} day(s) ago (minimum ${MIN_VERSION_AGE_DAYS})`);
  }
  if (info.direct) {
    const latest = (doc.versions || {})[(doc['dist-tags'] || {}).latest] || {};
    if (!latest.repository && !doc.repository) w.push(`${name} has no repository field`);
    if ((doc.maintainers || []).length <= 1) w.push(`${name} has ${(doc.maintainers || []).length} maintainer(s)`);
  }
  return { f, w };
}

async function fetchDoc(name) {
  const res = await fetch(`${REGISTRY}/${name.replace('/', '%2f')}`, { headers: { accept: 'application/json' } });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`registry returned ${res.status} for ${name}`); // fail closed
  return res.json();
}

async function main([base, out]) {
  if (!base || !out) throw new Error('usage: new-packages.js <base-sha> <findings.json>');
  const files = git('diff', '--name-only', base, 'HEAD').split('\n').filter(Boolean);
  const added = [...addedPackages(base, 'HEAD', files)];
  const findings = [];
  for (let i = 0; i < added.length; i += 8) { // 8 registry requests at a time
    const batch = added.slice(i, i + 8);
    const docs = await Promise.all(batch.map(([name]) => fetchDoc(name)));
    batch.forEach(([name, info], j) => {
      const { f, w } = judge(name, info, docs[j]);
      findings.push(...f);
      for (const m of w) console.log(`::warning file=${info.path},line=1,title=packages review::${m}`);
    });
  }
  fs.writeFileSync(out, JSON.stringify(findings));
  console.log(`new-packages: ${added.length} added package(s) checked, ${findings.length} finding(s)`);
}

module.exports = { addedPackages, judge };
if (require.main === module) main(process.argv.slice(2)).catch((e) => { console.log(`::error::new-packages: ${e.message}`); process.exit(1); });
