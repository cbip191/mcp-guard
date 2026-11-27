#!/usr/bin/env node
/**
 * Reproducible public benign corpus builder (Apache License 2.0).
 * Fetches 250 public Apache Kafka JIRA tickets + 100 public dev@kafka.apache.org emails
 * into test/fixtures/corpus/kafka-benign.jsonl for offline CI precision & latency scoring.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OUT_FILE = resolve(ROOT, "test/fixtures/corpus/kafka-benign.jsonl");

const JIRA_TARGET = 250;
const MAIL_TARGET = 100;
const MAX_FIELD_LEN = 3000;

const PERSONAL_EMAIL_RE =
  /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g;

function trimText(val) {
  if (typeof val !== "string") return "";
  return val
    .replace(/\r\n/g, "\n")
    .replace(PERSONAL_EMAIL_RE, (email) =>
      email.toLowerCase().endsWith("@apache.org") || email.toLowerCase().endsWith(".apache.org")
        ? email
        : "contributor@example.invalid"
    )
    .trim()
    .slice(0, MAX_FIELD_LEN);
}

async function fetchJson(url) {
  const res = await fetch(url, {
    headers: { "User-Agent": "mcp-guard-corpus-builder/0.2 (https://github.com/cbip191/mcp-guard)" },
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} fetching ${url}`);
  }
  return res.json();
}

async function fetchKafkaJira(target) {
  const items = [];
  let startAt = 0;
  const pageSize = 50;

  while (items.length < target) {
    const url =
      "https://issues.apache.org/jira/rest/api/2/search" +
      `?jql=${encodeURIComponent("project = KAFKA ORDER BY updated DESC")}` +
      `&startAt=${startAt}&maxResults=${pageSize}&fields=summary,description,comment,issuetype,status`;
    const data = await fetchJson(url);
    const issues = data.issues || [];
    if (issues.length === 0) break;

    for (const issue of issues) {
      if (items.length >= target) break;
      const fields = issue.fields || {};
      const comments = (fields.comment?.comments || [])
        .slice(0, 2)
        .map((c) => trimText(c.body))
        .filter(Boolean);

      items.push({
        id: issue.key,
        source: "apache-kafka-jira",
        type: fields.issuetype?.name || "Issue",
        summary: trimText(fields.summary),
        body: trimText(fields.description),
        comments,
      });
    }
    startAt += issues.length;
  }
  return items;
}

async function fetchKafkaDevList(target) {
  const stats = await fetchJson(
    "https://lists.apache.org/api/stats.lua?list=dev&domain=kafka.apache.org&d=lte=90d"
  );
  const emails = (stats.emails || []).slice(0, target);
  const items = [];
  const batchSize = 10;

  for (let i = 0; i < emails.length; i += batchSize) {
    const batch = emails.slice(i, i + batchSize);
    const fetched = await Promise.all(
      batch.map(async (meta) => {
        try {
          const detail = await fetchJson(
            `https://lists.apache.org/api/email.lua?id=${encodeURIComponent(meta.mid)}`
          );
          return {
            id: `kafka-dev:${meta.mid}`,
            source: "apache-kafka-dev-list",
            type: "Email",
            summary: trimText(detail.subject || meta.subject || ""),
            body: trimText(detail.body || ""),
            comments: [],
          };
        } catch {
          return null;
        }
      })
    );
    for (const item of fetched) {
      if (item && (item.summary || item.body)) {
        items.push(item);
      }
    }
  }
  return items;
}

const jiraItems = await fetchKafkaJira(JIRA_TARGET);
const mailItems = await fetchKafkaDevList(MAIL_TARGET);
const all = [...jiraItems, ...mailItems];

mkdirSync(dirname(OUT_FILE), { recursive: true });
writeFileSync(OUT_FILE, `${all.map((row) => JSON.stringify(row)).join("\n")}\n`, "utf8");

console.log(
  `Fetched ${all.length} public Apache Kafka items (${jiraItems.length} JIRA + ${mailItems.length} dev-list) -> ${OUT_FILE}`
);
