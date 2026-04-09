'use strict';
process.env.SECTOR      = process.env.SECTOR      || 'health';
process.env.CT_LOG_FILE = process.env.CT_LOG_FILE || '/home/paramant/relay-health/ct-log.json';
require('./relay-core');
