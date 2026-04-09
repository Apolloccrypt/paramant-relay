'use strict';
process.env.SECTOR      = process.env.SECTOR      || 'iot';
process.env.CT_LOG_FILE = process.env.CT_LOG_FILE || '/home/paramant/relay-iot/ct-log.json';
require('./relay-core');
