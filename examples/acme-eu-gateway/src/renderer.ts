import _ from 'lodash';
import ejs from 'ejs';

export function renderCustomerInvoice(rawTemplate: string, data: Record<string, unknown>): string {
  // Reachable vulnerable sink 1: lodash.template (CVE-2021-23337)
  const precompiled = _.template(rawTemplate);
  const intermediate = precompiled(data);
  // Reachable vulnerable sink 2: ejs.render (CVE-2024-33883)
  return ejs.render('<section><%- body %></section>', { body: intermediate });
}
