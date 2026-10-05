#!/usr/bin/env node
"use strict";

const {
  DEFAULT_DATASET_PATH,
  DEFAULT_TARGET_ROOT,
  generatePromptfooTests,
  generateRepresentativeSampleTests,
  loadDataset,
} = require("./sastbench-lib");

function loadRecords(options) {
  return Array.isArray(options.dataset)
    ? options.dataset
    : loadDataset(options.datasetPath || DEFAULT_DATASET_PATH);
}

function generateTests(options = {}) {
  const records = loadRecords(options);
  return generatePromptfooTests(records, options.targetRoot || DEFAULT_TARGET_ROOT);
}

function generateSampleTests(options = {}) {
  const records = loadRecords(options);
  return generateRepresentativeSampleTests(
    records,
    options.targetRoot || DEFAULT_TARGET_ROOT,
    options.sampleSpec,
  );
}

module.exports = { generateSampleTests, generateTests };
