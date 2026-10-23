import unittest

import actions
from native_runtime import DOMAIN
from primitives import h, singleton
import receiver
from scan_closed import payout_destination


class OriginalBackupPayoutControls(unittest.TestCase):
    def test_closed_receipt_rederives_actual_cashout_destination(self):
        """Established crypto/state control; no native, PK or chain claim."""
        crypto, v2 = receiver.Crypto(), receiver.module()
        seed = h(b'PUBLIC_DO_NOT_FUND_CLOSED_SCAN_ORIGINAL_SEED')
        wallet = v2.Receiver(seed, DOMAIN, crypto)
        note = v2.Receipt.for_invoice(wallet.invoice(0), 130_001_000,
                                     h(b'PUBLIC_DO_NOT_FUND_CLOSED_SCAN_RHO'))
        cipher = crypto.seal(wallet.invoice(0).delivery_pk, note.encode())
        snapshot = singleton(DOMAIN, note.note_bytes(), cipher)
        own = receiver.recover(wallet, snapshot, snapshot.state(DOMAIN)).owned[0]
        point = {'transactionId': '77' * 32, 'index': 0}
        cashout = actions.cashout(seed, wallet, snapshot, own, point, point,
                                  note.value_sompi, 1_000)
        spent = receiver.recover(wallet, cashout.after, cashout.after.state(DOMAIN)).owned[0]
        self.assertTrue(spent.spent)
        self.assertEqual(payout_destination(seed, wallet, spent, point), cashout.auth[492:528])
        self.assertNotEqual(payout_destination(h(seed), wallet, spent, point), cashout.auth[492:528])
        wrong_point = {'transactionId': '78' * 32, 'index': 0}
        self.assertNotEqual(payout_destination(seed, wallet, spent, wrong_point), cashout.auth[492:528])


if __name__ == '__main__':
    unittest.main()
