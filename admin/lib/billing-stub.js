'use strict';
// Hard-disabled stub checkout handler. See server.js for the full history: this
// replaced a no-payment plan-grant bypass where POST /user/billing/checkout ->
// /confirm called the admin-privileged /v2/admin/keys/update-plan and granted
// Pro for 0 euro. It takes only (req, res): it holds no relay/admin credentials
// and can grant no plan. The only paid-plan path is the Mollie webhook on the
// relay (/v2/billing/webhook -> lib/billing.processPayment, grant only on a
// verified 'paid' payment with a matching amount).
function billingStubGone(_req, res) {
  return res.status(410).json({
    error: 'billing_stub_removed',
    message: 'Checkout moved to Mollie; this endpoint no longer grants plans.',
  });
}

module.exports = { billingStubGone };
