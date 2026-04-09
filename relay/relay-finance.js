'use strict';
process.env.SECTOR      = process.env.SECTOR      || 'finance';
process.env.CT_LOG_FILE = process.env.CT_LOG_FILE || '/home/paramant/relay-finance/ct-log.json';
require('./relay-core');
