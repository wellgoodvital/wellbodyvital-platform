const serverless = require('serverless-http');
process.env.WBV_SERVERLESS = 'true';
const app = require('../../server');

module.exports.handler = serverless(app);
