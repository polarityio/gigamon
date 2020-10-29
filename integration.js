'use strict';

const request = require('request');
const _ = require('lodash');
const moment = require('moment');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

let Logger;
let requestWithDefaults;
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlocklistRegex = null;
let ipBlocklistRegex = null;

const MAX_DOMAIN_LABEL_LENGTH = 63;
const MAX_ENTITY_LENGTH = 100;
const MAX_PARALLEL_LOOKUPS = 10;
const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function startup(logger) {
  Logger = logger;
  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  if (typeof config.request.rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = config.request.rejectUnauthorized;
  }

  defaults.json = true;
  requestWithDefaults = request.defaults(defaults);
}



function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  _setupRegexBlocklists(options);

  Logger.debug(entities);

  entities.forEach((entity) => {
    if (entity.isIPv4) {
      if (!_isInvalidEntity(entity) && !_isEntityBlocklisted(entity, options)) {
        //do the lookup
        let requestOptions = {
          uri: `https://detections.icebrg.io/v1/detections`,
          method: 'GET',
          headers: {
            Authorization: 'IBToken ' + options.apiKey
          },
          qs: {
            device_ip: entity.value,
            sort_by: 'last_seen',
            sort_order: 'desc',
            include: 'rules',
            ...(options.account_uuid && { account_uuid: options.account_uuid })
          }
        };

        Logger.trace({ options: requestOptions }, 'Request URI');

        tasks.push(function (done) {
          requestWithDefaults(requestOptions, function (error, res, body) {
            let processedResult = handleRestError(error, entity, res, body);
            if (processedResult.error) return done(processedResult);

            if (processedResult.body) {
              processedResult = _formatBody(body, processedResult);
            }
            done(null, processedResult);
          });
        });
      }
    } else if (entity.isDomain) {
      if (!_isInvalidEntity(entity) && !_isEntityBlocklisted(entity, options)) {
        //do the lookup
        let requestOptions = {
          uri: `https://entity.icebrg.io/v1/entity/${entity.value}/summary`,
          method: 'GET',
          headers: {
            Authorization: 'IBToken ' + options.apiKey
          }
        };

        Logger.trace({ options: requestOptions }, 'Request URI');

        tasks.push(function (done) {
          requestWithDefaults(requestOptions, function (error, res, body) {
            let processedResult = handleRestError(error, entity, res, body);

            if (processedResult.error) {
              done(processedResult);
              return;
            }

            done(null, processedResult);
          });
        });
      }
    }
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err: err }, 'Error');
      cb(err);
      return;
    }

    results.forEach((result) => {
      Logger.trace({result:result.body}, "checking results");
      if (result.body === null || _isMiss(result.body)) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else if (options.detect === true && result.body.result_count === 0) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      }else {
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: [],
            details: {
              ...result.body,
              link: `https://portal.icebrg.io/search?query=${result.entity.value}`
            }
          }
        });
      }
    });
    Logger.trace({ lookupResults }, 'Results');
    cb(null, lookupResults);
  });
}

const _formatBody = (body, processedResult) => ({
  ...processedResult,
  body: {
    ...body,
    detections: body.detections
      .map(({ first_seen, last_seen, created, ...detection }) => ({
        ...detection,
        ...(detection.rule_uuid && {
          name: (body.rules.find(({ uuid }) => uuid === detection.rule_uuid) || { name: null }).name
        }),
        first_seen: moment(first_seen).format('MMM D YY, h:mm A'),
        last_seen: moment(last_seen).format('MMM D YY, h:mm A'),
        created: moment(created).format('MMM D YY, h:mm A')
      }))
      .filter(({ name }) => !(name && name.toLowerCase().includes('train'))),
    rules: body.rules.filter(({ name }) => !(name && name.toLowerCase().includes('train')))
  }
});

function _setupRegexBlocklists(options) {
  if (options.domainBlocklistRegex !== previousDomainRegexAsString && options.domainBlocklistRegex.length === 0) {
    Logger.debug('Removing Domain Blocklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlocklistRegex = null;
  } else {
    if (options.domainBlocklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlocklistRegex;
      Logger.debug({ domainBlocklistRegex: previousDomainRegexAsString }, 'Modifying Domain Blocklist Regex');
      domainBlocklistRegex = new RegExp(options.domainBlocklistRegex, 'i');
    }
  }

  if (options.ipBlocklistRegex !== previousIpRegexAsString && options.ipBlocklistRegex.length === 0) {
    Logger.debug('Removing IP Blocklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlocklistRegex = null;
  } else {
    if (options.ipBlocklistRegex !== previousIpRegexAsString) {
      previousIpRegexAsString = options.ipBlocklistRegex;
      Logger.debug({ ipBlocklistRegex: previousIpRegexAsString }, 'Modifying IP Blocklist Regex');
      ipBlocklistRegex = new RegExp(options.ipBlocklistRegex, 'i');
    }
  }
}

function doPDNSLookup(entity, options) {
  return function (done) {
    let requestOptions = {
      uri: `https://entity.icebrg.io/v1/entity/${entity.value}/pdns`,
      method: 'GET',
      headers: {
        Authorization: 'IBToken ' + options.apiKey
      }
    };

    requestWithDefaults(requestOptions, (error, response, body) => {
      let processedResult = handleRestError(error, entity, response, body);
      if (processedResult.error) return done(processedResult);

      done(null, processedResult.body);
    });
  };
}

function doDHCPLookup(entity, options) {
  return function (done) {
    if (entity.isIPv4) {
      let requestOptions = {
        uri: `https://entity.icebrg.io/v2/entity/tracking/ip/${entity.value}`,
        method: 'GET',
        headers: {
          Authorization: 'IBToken ' + options.apiKey
        }
      };
      
      requestWithDefaults(requestOptions, (error, response, body) => {
        let processedResult = handleRestError(error, entity, response, body);
        if (processedResult.error) return done(processedResult);
        done(null, processedResult.body);
      });
    } else {
      done(null, null);
    }
  };
}

function doSummaryLookup(entity, options) {
  return function (done) {
    let requestOptions = {
      uri: `https://entity.icebrg.io/v1/entity/${entity.value}/summary`,
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'IBToken ' + options.apiKey
      }
    };

    requestWithDefaults(requestOptions, (error, response, body) => {
      let processedResult = handleRestError(error, entity, response, body);
      if (processedResult.error) return done(processedResult);

      done(null, processedResult.body);
    });
  };
}

function onDetails(lookupObject, options, cb) {
  async.parallel(
    {
      pdns: doPDNSLookup(lookupObject.entity, options),
      dhcp: doDHCPLookup(lookupObject.entity, options),
      summary: doSummaryLookup(lookupObject.entity, options)
    },
    (err, result) => {
      if (err) {
        return cb(err);
      }

      const { pdns, dhcp, summary } = result;
      
      //store the results into the details object so we can access them in our template
      lookupObject.data.details.pdns = pdns;
      lookupObject.data.details.dhcp =
        dhcp &&
        dhcp.entity_tracking_response &&
        dhcp.entity_tracking_response.dhcp_mac_ip_intervals.map(({ interval_start, interval_end, ...dhcp }) => ({
          ...dhcp,
          ...(interval_start && { interval_start: moment(interval_start).format('MMM D YY, h:mm A') }),
          ...(interval_end && { interval_end: moment(interval_end).format('MMM D YY, h:mm A') })
        }));
      lookupObject.data.details.summary = {
        ...summary,
        ...(summary.first_seen && { first_seen: moment(summary.first_seen).format('MMM D YY, h:mm A') }),
        ...(summary.summary &&
          summary.summary.first_seen && { first_seen: moment(summary.first_seen).format('MMM D YY, h:mm A') }),
        ...(summary.last_seen && { last_seen: moment(summary.last_seen).format('MMM D YY, h:mm A') }),
        ...(summary.summary &&
          summary.summary.last_seen && { last_seen: moment(summary.last_seen).format('MMM D YY, h:mm A') })
      };

      Logger.trace({ lookup: lookupObject.data }, 'Looking at the data after on details.');

      cb(null, lookupObject.data);
    }
  );
}

function handleRestError(error, entity, res, body) {
  let result;

  if (error) {
    return {
      error: error,
      detail: 'HTTP Request Error'
    };
  }
  if (res.statusCode === 200) {
    // we got data!
    result = {
      entity: entity,
      body: body
    };
  } else if (res.statusCode === 404) {
    // no result found
    result = {
      entity: entity,
      body: null
    };
  } else if (res.statusCode === 202) {
    // no result found
    result = {
      entity: entity,
      body: null
    };
  } else {
    // unexpected status code
    result = {
      error: body,
      detail: `${body.error}: ${body.message}`
    };
  }
  return result;
}

function _isInvalidEntity(entity) {
  // Domains should not be over 100 characters long so if we get any of those we don't look them up
  if (entity.value.length > MAX_ENTITY_LENGTH) {
    return true;
  }

  // Domain labels (the parts in between the periods, must be 63 characters or less
  if (entity.isDomain) {
    const invalidLabel = entity.value.split('.').find((label) => {
      return label.length > MAX_DOMAIN_LABEL_LENGTH;
    });

    if (typeof invalidLabel !== 'undefined') {
      return true;
    }
  }

  if (entity.isIPv4 && IGNORED_IPS.has(entity.value)) {
    return true;
  }

  return false;
}

function _isEntityBlocklisted(entity, options) {
  const blocklist = options.blocklist;

  Logger.trace({ blocklist: blocklist }, 'checking to see what blocklist looks like');

  if (_.includes(blocklist, entity.value.toLowerCase())) {
    return true;
  }

  if (entity.isIP && !entity.isPrivateIP) {
    if (ipBlocklistRegex !== null) {
      if (ipBlocklistRegex.test(entity.value)) {
        Logger.debug({ ip: entity.value }, 'Blocked BlockListed IP Lookup');
        return true;
      }
    }
  }

  if (entity.isDomain) {
    if (domainBlocklistRegex !== null) {
      if (domainBlocklistRegex.test(entity.value)) {
        Logger.debug({ domain: entity.value }, 'Blocked BlockListed Domain Lookup');
        return true;
      }
    }
  }

  return false;
}

function _isMiss(body) {
  if (!body) {
    return true;
  }
}

function validateOptions(userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.apiKey.value !== 'string' ||
    (typeof userOptions.apiKey.value === 'string' && userOptions.apiKey.value.length === 0)
  ) {
    errors.push({
      key: 'apiKey',
      message: 'You must provide a PassiveTotal API key'
    });
  }
  cb(null, errors);
}

module.exports = {
  doLookup: doLookup,
  onDetails: onDetails,
  startup: startup,
  validateOptions: validateOptions
};
