import _ from 'lodash';

export function chunkSettlementBatches<T>(records: T[], batchSize = 50): T[][] {
  // Only invokes safe _.chunk — never touches _.template, _.merge, _.defaultsDeep, _.zipObjectDeep, or _.trim
  return _.chunk(records, batchSize);
}
