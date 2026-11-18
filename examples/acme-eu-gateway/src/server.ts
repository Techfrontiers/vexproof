import { verifyMerchantToken } from './auth';
import { renderCustomerInvoice } from './renderer';

interface MockApp {
  post: (path: string, handler: (req: { body: Record<string, string>; headers: Record<string, string> }) => string) => void;
}

export function bootstrapGateway(app: MockApp) {
  app.post('/api/v1/invoice/preview', (req) => {
    const claims = verifyMerchantToken(req.headers.authorization ?? '');
    return renderCustomerInvoice(req.body.templateSource ?? '<h1><%= total %></h1>', {
      merchant: claims.sub,
      total: req.body.total ?? '0.00 EUR',
    });
  });
}
