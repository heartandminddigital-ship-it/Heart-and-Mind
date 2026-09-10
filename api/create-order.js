/* POST /api/create-order
 * Creates a Razorpay order server-side, where the key secret lives.
 * The client only ever receives the order id and the public key id —
 * never the secret. Vercel's Node runtime auto-parses a JSON body into
 * req.body, which is what this assumes; see server.mjs for the local
 * dev shim that reproduces the same contract.
 *
 * The price is fixed here, not trusted from the client, so a visitor
 * can't reopen the form with devtools and pay ₹1 for a ₹199 seat.
 * Keep this in sync with the ₹199 shown in index.html.
 */
const AMOUNT_INR = 199;
const CURRENCY = 'INR';

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const keyId = process.env.RAZOR_PAY_API_KEY;
  const keySecret = process.env.RAZOR_PAY_SECRET;
  if (!keyId || !keySecret) {
    console.error('create-order: RAZOR_PAY_API_KEY / RAZOR_PAY_SECRET not set');
    res.status(500).json({ error: 'Payment is not configured on the server.' });
    return;
  }

  const body = req.body || {};
  const name = typeof body.name === 'string' ? body.name.trim().slice(0, 120) : '';
  const age = typeof body.age === 'string' || typeof body.age === 'number' ? String(body.age).slice(0, 4) : '';
  const sex = typeof body.sex === 'string' ? body.sex.trim().slice(0, 30) : '';
  const phone = typeof body.phone === 'string' ? body.phone.trim().slice(0, 20) : '';

  /* Light defence-in-depth — the real validation already happened in
     the browser. This just stops a stray/broken client from creating
     junk orders, not a determined attacker. */
  if (name.length < 2 || phone.replace(/\D/g, '').length < 10) {
    res.status(400).json({ error: 'Missing or invalid reservation details.' });
    return;
  }

  const receipt = `hm-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  try {
    const auth = Buffer.from(`${keyId}:${keySecret}`).toString('base64');
    const rzpRes = await fetch('https://api.razorpay.com/v1/orders', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Basic ${auth}`,
      },
      body: JSON.stringify({
        amount: AMOUNT_INR * 100, // paise
        currency: CURRENCY,
        receipt,
        /* Stored on the order and visible in the Razorpay dashboard —
           the only record of who registered, since there is no
           database behind this page. */
        notes: {
          session: '19 Sep 2026, 5:00 PM - 6:30 PM',
          name, age, sex, phone,
        },
      }),
    });

    const data = await rzpRes.json();
    if (!rzpRes.ok) {
      console.error('create-order: Razorpay rejected the order', data);
      res.status(502).json({ error: data?.error?.description || 'Could not start the payment.' });
      return;
    }

    res.status(200).json({
      orderId: data.id,
      amount: data.amount,
      currency: data.currency,
      keyId, // public key id — safe to hand to the browser
      successRedirect: process.env.RAZORPAY_SUCCESS_REDIRECT_URL || '',
      failureRedirect: process.env.RAZORPAY_FAILURE_REDIRECT_URL || '',
    });
  } catch (err) {
    console.error('create-order: unexpected error', err);
    res.status(500).json({ error: 'Could not start the payment. Please try again.' });
  }
};
