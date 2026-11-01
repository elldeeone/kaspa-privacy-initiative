#!/usr/bin/env python3
"""Hostile direct-include controls for epoch-journal private authority."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
MPC = HERE.parents[1]


class EpochJournalFriendSealingControls(unittest.TestCase):
    def compile(self, body):
        compiler = shutil.which('x86_64-linux-gnu-g++-15') or \
            shutil.which('g++')
        if compiler is None:
            raise unittest.SkipTest('C++ compiler unavailable')
        with tempfile.TemporaryDirectory(
                prefix='kpb-epoch-journal-hostile-') as directory:
            source = Path(directory) / 'hostile.cpp'
            source.write_text(body, encoding='utf-8')
            return subprocess.run([
                compiler, '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-fsyntax-only', '-I', str(MPC), str(source),
            ], capture_output=True, text=True, check=False)

    def test_direct_include_without_attack_compiles(self):
        result = self.compile(r'''
#include "history/epoch_journal.hpp"
int main() { return 0; }
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_forward_friend_names_cannot_forge_or_mutate_journal(self):
        attacks = {
            'locked-attempt': r'''
#include "history/epoch_journal.hpp"
namespace kpi::mpc::history {
class LockedAttempt final {
public:
    static void erase(EpochJournal& journal) { journal.core_.reset(); }
    static DurableRecord forge() {
        return DurableRecord(
            std::shared_ptr<detail::JournalCore>{}, 0, {}, Phase::Ready);
    }
};
}
int main() { return 0; }
''',
            'prepared-ticket': r'''
#include "history/epoch_journal.hpp"
namespace kpi::mpc::history {
class PreparedEpochTicket final {
public:
    static EpochJournal duplicate(EpochJournal& journal) {
        return EpochJournal(journal.core_);
    }
    static DurableRecord forge() {
        return DurableRecord(
            std::shared_ptr<detail::JournalCore>{}, 0, {}, Phase::Ready);
    }
};
}
int main() { return 0; }
''',
            'verified-settlement': r'''
#include "history/epoch_journal.hpp"
namespace kpi::mpc::history {
class VerifiedSettlement final {
public:
    static DurableRecord append(
            EpochJournal& journal, const SettlementRecord& settlement,
            uint64_t sequence, const Digest& checkpoint) {
        return journal.record_verified_settlement(
            settlement, sequence, checkpoint);
    }
};
}
int main() { return 0; }
''',
            'verified-final-candidate': r'''
#include "history/epoch_journal.hpp"
namespace kpi::mpc::history {
class VerifiedFinalCandidate final {
public:
    static EpochJournal duplicate(EpochJournal& journal) {
        return EpochJournal(journal.core_);
    }
    static DurableRecord forge(EpochJournal& journal) {
        return DurableRecord(journal.core_, 0, {}, Phase::Egress);
    }
};
}
int main() { return 0; }
''',
            'journal-core': r'''
#include "history/epoch_journal.hpp"
namespace kpi::mpc::history::detail {
struct JournalCore final {
    static DurableRecord forge() {
        return DurableRecord(
            std::shared_ptr<JournalCore>{}, 0, {}, Phase::Ready);
    }
};
}
int main() { return 0; }
''',
            'epoch-ticket-journal-bridge': r'''
#include "history/epoch_journal.hpp"
namespace kpi::mpc::history {
class EpochTicketJournalBridge final {};
}
int main() { return 0; }
''',
            'verified-settlement-journal-bridge': r'''
#include "history/epoch_journal.hpp"
namespace kpi::mpc::history {
class VerifiedSettlementJournalBridge final {};
}
int main() { return 0; }
''',
            'storage-fixture-methods': r'''
#include "history/epoch_journal.hpp"
using namespace kpi::mpc::history;
int main() {
    EpochJournal* journal = nullptr;
    SettlementRecord settlement{};
    (void)VerifiedSettlementJournalBridge::
        test_only_record_verified_settlement(
            *journal, settlement, 0, Digest{});
}
''',
        }
        for name, body in attacks.items():
            with self.subTest(name=name):
                result = self.compile(body)
                self.assertNotEqual(
                    result.returncode, 0,
                    name + ' forged or mutated journal authority')


if __name__ == '__main__':
    unittest.main()
