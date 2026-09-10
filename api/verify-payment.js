/* POST /api/verify-payment
 * Confirms a checkout was genuine before treating it as paid. Razorpay's
 * client-side "success" callback fires on its own say-so — anyone could
 * forge that call from devtools with a fake payment id. The only trustworthy
 * check is recomputing the HMAC signature server-side, where the secret
 * lives, and comparing it to what Razorpay actually signed.
 * https://razorpay.com/docs/payments/payment-gateway/web-integration/standard/build-integration/#4-verify-payment-signature
 */
const crypto = require('crypto');

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const keySecret = process.env.RAZOR_PAY_SECRET;
  if (!keySecret) {
    console.error('verify-payment: RAZOR_PAY_SECRET not set');
    res.status(500).json({ error: 'Payment is not configured on the server.' });
    return;
  }

  const body = req.body || {};
  const orderId = body.razorpay_order_id;
  const paymentId = body.razorpay_payment_id;
  const signature = body.razorpay_signature;

  if (!orderId || !paymentId || !signature) {
    res.status(400).json({ verified: false, error: 'Missing payment details.' });
    return;
  }

  const expected = crypto
    .createHmac('sha256', keySecret)
    .update(`${orderId}|${paymentId}`)
    .digest('hex');

  /* Constant-time comparison — a plain === leaks timing information an
     attacker could use to guess the signature one byte at a time. Buffers
     must be equal length first, or timingSafeEqual itself throws. */
  const expectedBuf = Buffer.from(expected, 'hex');
  const gotBuf = Buffer.from(String(signature), 'hex');
  const verified =
    expectedBuf.length === gotBuf.length && crypto.timingSafeEqual(expectedBuf, gotBuf);

  if (!verified) {
    console.warn('verify-payment: signature mismatch', { orderId, paymentId });
    res.status(400).json({ verified: false });
    return;
  }

  res.status(200).json({ verified: true, paymentId, orderId });
};
