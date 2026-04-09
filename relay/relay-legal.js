'use strict';
process.env.SECTOR      = process.env.SECTOR      || 'legal';
process.env.CT_LOG_FILE = process.env.CT_LOG_FILE || '/home/paramant/relay-legal/ct-log.json';
require('./relay-core');
