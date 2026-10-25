"""Tests of tools/process_registration_mail.py: python3 -m unittest tools/test_process_registration_mail.py (needs `cryptography`)."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import process_registration_mail as prm  # noqa: E402

# registrations made by the real wallet (`vearl-wallet register ... --print-only`) with two throw-away keys
ADDR1 = "vrl158v7z57nwtvf05znhf98lnjv0xdwtwr5aq7ss7txnjwuy3lz4d4qh9y83e"
MSG1 = f"Vearl testnet rewards registration. Address: {ADDR1}. Contact: tester#0001. I accept the terms in docs/19."
SIG1 = "c38c882801f9b1e4e30a28f22c584bef2a3f975b5fbf5ebadfeae89fe201286e46444b3397c20c741eb06f36cde4f8f3b7558fef63aa57d078933b06bbab1f0f"
ADDR2 = "vrl123mpafpfuycg5h3qzn6qdrfw0p04fq63grdu4lpjrk24uv5upjaqd8yv2k"
MSG2 = f"Vearl testnet rewards registration. Address: {ADDR2}. Contact: test#0001. I accept the terms in docs/19."
SIG2 = "d740eede20753f148af4c457b3d2ff7fa0bc97e3214cb7b50d46f39719bdd3cd499b91df2387b8d91ec18a56d91b05e2d4bb31e80372da87a070dd3cc134d703"


def mail(address, message, signature, subject="Vearl testnet registration", sender="registrar@vearl.org"):
    body = f"Vearl testnet rewards registration (docs/19)\r\naddress: {address}\r\nmessage: {message}\r\nsignature: {signature}\r\n"
    return (f"From: {sender}\r\nTo: register@vearl.org\r\nSubject: {subject}\r\nDate: Fri, 23 Oct 2026 16:05:00 +0000\r\n"
            f"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}").encode()


def unlabelled_mail(address, message, signature, greeting="", sender="someone@example.com"):
    """What a person sends by hand after pressing Copy in the wallet window of rc16.1 and before (three lines, no labels)."""
    return (f"From: {sender}\r\nTo: register@vearl.org\r\nSubject: Vearl registration\r\nDate: Fri, 23 Oct 2026 16:05:00 +0000\r\n"
            f"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{greeting}{address}\r\n{message}\r\n{signature}\r\n").encode()


class Box:
    """A throw-away Maildir, state folder and public folder."""

    def __init__(self):
        self.t = tempfile.TemporaryDirectory()
        r = self.t.name
        self.maildir, self.state, self.public = (os.path.join(r, x) for x in ("Maildir", "state", "public"))
        for s in ("new", "cur", "tmp"):
            os.makedirs(os.path.join(self.maildir, s))
        self.n = 0

    def put(self, raw, sub="new"):
        self.n += 1
        with open(os.path.join(self.maildir, sub, f"{self.n}.msg"), "wb") as f:
            f.write(raw)

    def run(self):
        return prm.process(self.maildir, self.state, self.public)

    def read(self, folder, name):
        return json.load(open(os.path.join(folder, name)))


class ProcessTests(unittest.TestCase):
    def test_a_valid_registration_is_accepted_and_published_without_the_contact(self):
        b = Box()
        b.put(mail(ADDR1, MSG1, SIG1))
        r = b.run()
        self.assertEqual((r["added"], r["dropped"], r["total"]), (1, 0, 1))
        pub = b.read(b.public, "registered.json")
        self.assertEqual(pub["addresses"], [ADDR1])
        self.assertEqual(pub["count"], 1)
        self.assertNotIn("tester#0001", json.dumps(pub))                      # the contact stays private
        priv = b.read(b.state, "registrations.json")
        self.assertEqual(priv[0]["contact"], "tester#0001")
        self.assertEqual(b.read(b.state, "rewards-registered.json")["addresses"], [ADDR1])

    def test_a_forged_registration_is_refused_whoever_sends_it(self):
        b = Box()
        b.put(mail(ADDR1, MSG1, SIG2))                                           # signature of another key
        b.put(mail(ADDR2, MSG2, SIG2[:-2] + "00"))                               # damaged signature
        b.put(mail(ADDR1, MSG1.replace("tester#0001", "me"), SIG1))              # message changed after signing
        b.put(mail("vrl1other", MSG1, SIG1))                                     # message names another address
        b.put(mail(ADDR1, "hello", SIG1))                                        # wrong form
        r = b.run()
        self.assertEqual((r["added"], r["dropped"], r["total"]), (0, 5, 0))
        self.assertEqual(b.read(b.public, "registered.json")["addresses"], [])

    def test_the_three_lines_sent_by_hand_without_labels_are_accepted(self):
        b = Box()
        b.put(unlabelled_mail(ADDR1, MSG1, SIG1))
        b.put(unlabelled_mail(ADDR2, MSG2, SIG2, greeting="Hello team,\r\n\r\n"))     # a greeting before the lines does no harm
        r = b.run()
        self.assertEqual((r["added"], r["dropped"], r["total"]), (2, 0, 2))
        self.assertEqual(sorted(b.read(b.public, "registered.json")["addresses"]), sorted([ADDR1, ADDR2]))

    def test_a_message_cut_into_several_lines_by_the_mail_program_is_put_back_together(self):
        b = Box()
        wrapped = MSG1.replace(" Address: ", " Address:\r\n").replace(". Contact: ", ". Contact:\r\n")
        self.assertGreater(wrapped.count("\r\n"), 1)
        b.put(unlabelled_mail(ADDR1, wrapped, SIG1))                                  # Gmail style, no labels
        b.put(mail(ADDR2, MSG2.replace(" Address: ", " Address:\r\n"), SIG2))          # with labels
        r = b.run()
        self.assertEqual((r["added"], r["dropped"], r["total"]), (2, 0, 2))

    def test_labelled_lines_glued_into_one_line_by_a_webmail_are_accepted(self):
        b = Box()
        nb = " "
        # Yahoo style: the line breaks are lost, only the labels are left (no-break spaces after them)
        glued = f"address:{nb} {nb} {ADDR1}message:{nb} {nb} {MSG1}signature: {SIG1}"
        head = "From: someone@yahoo.com\r\nTo: register@vearl.org\r\nSubject: Vearl testnet registration\r\nDate: Fri, 23 Oct 2026 16:05:00 +0000\r\n"
        raw = (head + "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + glued + "\r\n").encode()
        b.put(raw)
        b.put(raw.replace(SIG1.encode(), SIG2.encode()))                                # forged: still refused
        b.put(raw.replace(b"signature: " + SIG1.encode(), b"signature:"))               # signature missing: still dropped
        r = b.run()
        self.assertEqual((r["added"], r["dropped"], r["total"]), (1, 2, 1))
        self.assertEqual(b.read(b.public, "registered.json")["addresses"], [ADDR1])

    def test_a_value_put_on_the_line_below_its_label_is_accepted(self):
        b = Box()
        # Gmail: the long lines are cut, `signature:` is alone on its line and the hex is below it (a real mail of 2026-10-20)
        wrapped = MSG1.replace(" Address: ", " Address:\r\n").replace(". Contact: ", ". Contact:\r\n")
        body = f"address:   {ADDR1}\r\nmessage:   {wrapped}\r\nsignature:\r\n{SIG1}\r\n"
        head = "From: someone@gmail.com\r\nTo: register@vearl.org\r\nSubject: Vearl registration\r\nDate: Fri, 23 Oct 2026 16:05:00 +0000\r\n"
        raw = (head + "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body).encode()
        b.put(raw)
        b.put(raw.replace(SIG1.encode(), SIG2.encode()))                                # forged: still refused
        r = b.run()
        self.assertEqual((r["added"], r["dropped"], r["total"]), (1, 1, 1))

    def test_blank_lines_inside_the_message_are_accepted(self):
        b = Box()
        # Proton Mail: every field is separated by a blank line and the message is cut after its first sentence (a real mail of 2026-10-14)
        cut = MSG1.replace(" Address: ", "\r\n\r\nAddress: ")
        body = f"address: {ADDR1}\r\n\r\nmessage: {cut}\r\n\r\nsignature: {SIG1}\r\n"
        head = "From: someone@proton.me\r\nTo: register@vearl.org\r\nSubject: sign\r\nDate: Fri, 23 Oct 2026 16:05:00 +0000\r\n"
        raw = (head + "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + body).encode()
        b.put(raw)
        b.put(raw.replace(SIG1.encode(), SIG2.encode()))                                # forged: still refused
        r = b.run()
        self.assertEqual((r["added"], r["dropped"], r["total"]), (1, 1, 1))

    def test_a_doubled_space_inside_the_message_is_accepted(self):
        b = Box()
        # Gmail on a phone: a space inside the line is doubled and the message is cut in three (a real mail of 2026-10-24)
        wrapped = MSG1.replace(" Address: ", " Address:\r\n").replace(". Contact: ", ". Contact:\r\n").replace("I accept the", "I accept  the")
        body = f"  address:   {ADDR1}\r\n  message:   {wrapped}\r\n  signature:\r\n{SIG1}\r\n"
        head = "From: someone@gmail.com\r\nTo: register@vearl.org\r\nSubject: Vearl testnet registration\r\nDate: Fri, 23 Oct 2026 16:05:00 +0000\r\n"
        raw = (head + "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body).encode()
        b.put(raw)
        b.put(raw.replace(SIG1.encode(), SIG2.encode()))                                # forged: still refused
        b.put(raw.replace(b"I accept  the", b"I accept  all"))                          # another text: still refused
        r = b.run()
        self.assertEqual((r["added"], r["dropped"], r["total"]), (1, 2, 1))

    def test_unlabelled_lines_do_not_let_a_forged_signature_through(self):
        b = Box()
        b.put(unlabelled_mail(ADDR1, MSG1, SIG2))                                  # the signature of another key
        b.put(unlabelled_mail(ADDR1, MSG2, SIG1))                                  # a message that names another address
        r = b.run()
        self.assertEqual((r["added"], r["dropped"]), (0, 2))

    def test_malformed_large_and_empty_mails_are_dropped(self):
        b = Box()
        b.put(b"not an e-mail at all")
        b.put(mail(ADDR1, MSG1, SIG1) + b"x" * 9000)                              # larger than any real registration
        b.put(b"From: a@b\r\nSubject: s\r\n\r\njust some text\r\n")
        r = b.run()
        self.assertEqual((r["added"], r["dropped"]), (0, 3))

    def test_the_same_address_twice_counts_once_and_a_second_run_does_not_read_mail_again(self):
        b = Box()
        b.put(mail(ADDR1, MSG1, SIG1))
        b.put(mail(ADDR1, MSG1, SIG1), sub="cur")
        r = b.run()
        self.assertEqual((r["added"], r["duplicates"], r["total"]), (1, 1, 1))
        self.assertEqual(os.listdir(os.path.join(b.maildir, "new")) + os.listdir(os.path.join(b.maildir, "cur")), [])
        self.assertEqual(len(os.listdir(os.path.join(b.maildir, ".Processed", "cur"))), 2)
        r2 = b.run()
        self.assertEqual((r2["added"], r2["total"]), (0, 1))

    def test_registrations_accumulate_over_runs_and_shared_contacts_are_flagged(self):
        b = Box()
        b.put(mail(ADDR1, MSG1, SIG1))
        b.run()
        b.put(mail(ADDR2, MSG2, SIG2))
        r = b.run()
        self.assertEqual(r["total"], 2)
        self.assertEqual(b.read(b.public, "registered.json")["addresses"], sorted([ADDR1, ADDR2]))
        self.assertEqual(r["shared_contacts"], 0)                                 # two different contacts
        # the same contact for two addresses: listed for a manual look
        regs = b.read(b.state, "registrations.json")
        regs[1]["contact"] = regs[0]["contact"]
        json.dump(regs, open(os.path.join(b.state, "registrations.json"), "w"))
        b.put(b"x")
        self.assertEqual(b.run()["shared_contacts"], 1)

    def test_the_address_in_the_mail_headers_does_not_matter(self):
        b = Box()
        b.put(mail(ADDR1, MSG1, SIG1, sender="somebody-else@example.org"))
        self.assertEqual(b.run()["added"], 1)

    def test_output_is_compatible_with_the_leaderboard_script(self):
        b = Box()
        b.put(mail(ADDR1, MSG1, SIG1))
        b.run()
        res = b.read(b.state, "rewards-registered.json")
        self.assertEqual(set(res), {"addresses", "rejected", "shared_contacts"})


if __name__ == "__main__":
    unittest.main()
