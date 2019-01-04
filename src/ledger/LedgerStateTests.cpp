// Copyright 2018 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "ledger/LedgerTxn.h"
#include "ledger/LedgerTxnEntry.h"
#include "ledger/LedgerTxnHeader.h"
#include "ledger/LedgerTestUtils.h"
#include "lib/catch.hpp"
#include "main/Application.h"
#include "test/TestUtils.h"
#include "test/test.h"
#include "transactions/TransactionUtils.h"
#include "util/XDROperators.h"
#include <map>
#include <memory>
#include <queue>
#include <set>
#include <xdrpp/autocheck.h>

using namespace stellar;

static void
validate(
    AbstractLedgerTxn& ls,
    std::unordered_map<LedgerKey, LedgerTxnDelta::EntryDelta> const& expected)
{
    auto const delta = ls.getDelta();

    auto expectedIter = expected.begin();
    auto iter = delta.entry.begin();
    while (expectedIter != expected.end() && iter != delta.entry.end())
    {
        REQUIRE(expectedIter->first == iter->first);
        REQUIRE((bool)expectedIter->second.current ==
                (bool)iter->second.current);
        if (expectedIter->second.current)
        {
            REQUIRE(*expectedIter->second.current == *iter->second.current);
        }
        REQUIRE((bool)expectedIter->second.previous ==
                (bool)iter->second.previous);
        if (expectedIter->second.previous)
        {
            REQUIRE(*expectedIter->second.previous == *iter->second.previous);
        }
        ++expectedIter;
        ++iter;
    }
    REQUIRE(expectedIter == expected.end());
    REQUIRE(iter == delta.entry.end());
}

static LedgerEntry
generateLedgerEntryWithSameKey(LedgerEntry const& leBase)
{
    LedgerEntry le;
    le.data.type(leBase.data.type());
    le.lastModifiedLedgerSeq = 1;
    do
    {
        switch (le.data.type())
        {
        case ACCOUNT:
            le.data.account() = LedgerTestUtils::generateValidAccountEntry();
            le.data.account().accountID = leBase.data.account().accountID;
            break;
        case DATA:
            le.data.data() = LedgerTestUtils::generateValidDataEntry();
            le.data.data().accountID = leBase.data.data().accountID;
            le.data.data().dataName = leBase.data.data().dataName;
            break;
        case OFFER:
            le.data.offer() = LedgerTestUtils::generateValidOfferEntry();
            le.data.offer().sellerID = leBase.data.offer().sellerID;
            le.data.offer().offerID = leBase.data.offer().offerID;
            break;
        case TRUSTLINE:
            le.data.trustLine() =
                LedgerTestUtils::generateValidTrustLineEntry();
            le.data.trustLine().accountID = leBase.data.trustLine().accountID;
            le.data.trustLine().asset = leBase.data.trustLine().asset;
            break;
        default:
            REQUIRE(false);
        }
    } while (le == leBase);
    return le;
}

TEST_CASE("LedgerTxn addChild", "[ledgerstate]")
{
    VirtualClock clock;
    auto app = createTestApplication(clock, getTestConfig());
    app->start();

    SECTION("with LedgerTxn parent")
    {
        SECTION("fails if parent has children")
        {
            LedgerTxn ls1(app->getLedgerTxnRoot());
            LedgerTxn ls2(ls1);
            REQUIRE_THROWS_AS(LedgerTxn(ls1), std::runtime_error);
        }

        SECTION("fails if parent is sealed")
        {
            LedgerTxn ls1(app->getLedgerTxnRoot());
            ls1.getDelta();
            REQUIRE_THROWS_AS(LedgerTxn(ls1), std::runtime_error);
        }
    }

    SECTION("with LedgerTxnRoot parent")
    {
        SECTION("fails if parent has children")
        {
            LedgerTxn ls1(app->getLedgerTxnRoot());
            REQUIRE_THROWS_AS(LedgerTxn(app->getLedgerTxnRoot()),
                              std::runtime_error);
        }
    }
}

TEST_CASE("LedgerTxn commit into LedgerTxn", "[ledgerstate]")
{
    VirtualClock clock;
    auto app = createTestApplication(clock, getTestConfig());
    app->start();

    LedgerEntry le1 = LedgerTestUtils::generateValidLedgerEntry();
    le1.lastModifiedLedgerSeq = 1;
    LedgerKey key = LedgerEntryKey(le1);

    auto le2 = generateLedgerEntryWithSameKey(le1);

    SECTION("one entry")
    {
        SECTION("created in child")
        {
            LedgerTxn ls1(app->getLedgerTxnRoot());

            LedgerTxn ls2(ls1);
            REQUIRE(ls2.create(le1));
            ls2.commit();

            validate(
                ls1,
                {{key, {std::make_shared<LedgerEntry const>(le1), nullptr}}});
        }

        SECTION("loaded in child")
        {
            LedgerTxn ls1(app->getLedgerTxnRoot());
            REQUIRE(ls1.create(le1));

            LedgerTxn ls2(ls1);
            REQUIRE(ls2.load(key));
            ls2.commit();

            validate(
                ls1,
                {{key, {std::make_shared<LedgerEntry const>(le1), nullptr}}});
        }

        SECTION("modified in child")
        {
            LedgerTxn ls1(app->getLedgerTxnRoot());
            REQUIRE(ls1.create(le1));

            LedgerTxn ls2(ls1);
            auto lse1 = ls2.load(key);
            REQUIRE(lse1);
            lse1.current() = le2;
            ls2.commit();

            validate(
                ls1,
                {{key, {std::make_shared<LedgerEntry const>(le2), nullptr}}});
        }

        SECTION("erased in child")
        {
            LedgerTxn ls1(app->getLedgerTxnRoot());
            REQUIRE(ls1.create(le1));

            LedgerTxn ls2(ls1);
            REQUIRE_NOTHROW(ls2.erase(key));
            ls2.commit();

            validate(ls1, {});
        }
    }
}

TEST_CASE("LedgerTxn rollback into LedgerTxn", "[ledgerstate]")
{
    VirtualClock clock;
    auto app = createTestApplication(clock, getTestConfig());
    app->start();

    LedgerEntry le1 = LedgerTestUtils::generateValidLedgerEntry();
    le1.lastModifiedLedgerSeq = 1;
    LedgerKey key = LedgerEntryKey(le1);

    auto le2 = generateLedgerEntryWithSameKey(le1);

    SECTION("one entry")
    {
        SECTION("created in child")
        {
            LedgerTxn ls1(app->getLedgerTxnRoot());

            LedgerTxn ls2(ls1);
            REQUIRE(ls2.create(le1));
            ls2.rollback();

            validate(ls1, {});
        }

        SECTION("loaded in child")
        {
            LedgerTxn ls1(app->getLedgerTxnRoot());
            REQUIRE(ls1.create(le1));

            LedgerTxn ls2(ls1);
            REQUIRE(ls2.load(key));
            ls2.rollback();

            validate(
                ls1,
                {{key, {std::make_shared<LedgerEntry const>(le1), nullptr}}});
        }

        SECTION("modified in child")
        {
            LedgerTxn ls1(app->getLedgerTxnRoot());
            REQUIRE(ls1.create(le1));

            LedgerTxn ls2(ls1);
            auto lse1 = ls2.load(key);
            REQUIRE(lse1);
            lse1.current() = le2;
            ls2.rollback();

            validate(
                ls1,
                {{key, {std::make_shared<LedgerEntry const>(le1), nullptr}}});
        }

        SECTION("erased in child")
        {
            LedgerTxn ls1(app->getLedgerTxnRoot());
            REQUIRE(ls1.create(le1));

            LedgerTxn ls2(ls1);
            REQUIRE_NOTHROW(ls2.erase(key));
            ls2.rollback();

            validate(
                ls1,
                {{key, {std::make_shared<LedgerEntry const>(le1), nullptr}}});
        }
    }
}

TEST_CASE("LedgerTxn round trip", "[ledgerstate]")
{
    std::default_random_engine gen;
    std::bernoulli_distribution shouldCommitDist;

    auto generateNew = [](AbstractLedgerTxn& ls,
                          std::unordered_map<LedgerKey, LedgerEntry>& entries) {
        size_t const NEW_ENTRIES = 100;
        std::unordered_map<LedgerKey, LedgerEntry> newBatch;
        while (newBatch.size() < NEW_ENTRIES)
        {
            auto le = LedgerTestUtils::generateValidLedgerEntry();
            auto key = LedgerEntryKey(le);
            if (entries.find(LedgerEntryKey(le)) == entries.end())
            {
                le.lastModifiedLedgerSeq = 1;
                newBatch[LedgerEntryKey(le)] = le;
            }
        }

        for (auto const& kv : newBatch)
        {
            REQUIRE(ls.create(kv.second));
            entries[kv.first] = kv.second;
        }
    };

    auto generateModify =
        [&gen](AbstractLedgerTxn& ls,
               std::unordered_map<LedgerKey, LedgerEntry>& entries) {
            size_t const MODIFY_ENTRIES = 25;
            std::unordered_map<LedgerKey, LedgerEntry> modifyBatch;
            std::uniform_int_distribution<size_t> dist(0, entries.size() - 1);
            while (modifyBatch.size() < MODIFY_ENTRIES)
            {
                auto iter = entries.begin();
                std::advance(iter, dist(gen));
                modifyBatch[iter->first] =
                    generateLedgerEntryWithSameKey(iter->second);
            }

            for (auto const& kv : modifyBatch)
            {
                auto lse = ls.load(kv.first);
                REQUIRE(lse);
                lse.current() = kv.second;
                entries[kv.first] = kv.second;
            }
        };

    auto generateErase =
        [&gen](AbstractLedgerTxn& ls,
               std::unordered_map<LedgerKey, LedgerEntry>& entries,
               std::unordered_set<LedgerKey>& dead) {
            size_t const ERASE_ENTRIES = 25;
            std::unordered_set<LedgerKey> eraseBatch;
            std::uniform_int_distribution<size_t> dist(0, entries.size() - 1);
            while (eraseBatch.size() < ERASE_ENTRIES)
            {
                auto iter = entries.begin();
                std::advance(iter, dist(gen));
                eraseBatch.insert(iter->first);
            }

            for (auto const& key : eraseBatch)
            {
                REQUIRE_NOTHROW(ls.erase(key));
                entries.erase(key);
                dead.insert(key);
            }
        };

    auto checkLedger =
        [](AbstractLedgerTxnParent& lsParent,
           std::unordered_map<LedgerKey, LedgerEntry> const& entries,
           std::unordered_set<LedgerKey> const& dead) {
            LedgerTxn ls(lsParent);
            for (auto const& kv : entries)
            {
                auto lse = ls.load(kv.first);
                REQUIRE(lse);
                REQUIRE(lse.current() == kv.second);
            }

            for (auto const& key : dead)
            {
                if (entries.find(key) == entries.end())
                {
                    REQUIRE(!ls.load(key));
                }
            }
        };

    auto runTest = [&](AbstractLedgerTxnParent& lsParent) {
        std::unordered_map<LedgerKey, LedgerEntry> entries;
        std::unordered_set<LedgerKey> dead;
        size_t const NUM_BATCHES = 10;
        for (size_t k = 0; k < NUM_BATCHES; ++k)
        {
            checkLedger(lsParent, entries, dead);

            std::unordered_map<LedgerKey, LedgerEntry> updatedEntries = entries;
            std::unordered_set<LedgerKey> updatedDead = dead;
            LedgerTxn ls1(lsParent);
            generateNew(ls1, updatedEntries);
            generateModify(ls1, updatedEntries);
            generateErase(ls1, updatedEntries, updatedDead);

            if (entries.empty() || shouldCommitDist(gen))
            {
                entries = updatedEntries;
                dead = updatedDead;
                REQUIRE_NOTHROW(ls1.commit());
            }
        }
    };

    SECTION("round trip to LedgerTxn")
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();

        LedgerTxn ls1(app->getLedgerTxnRoot());
        runTest(ls1);
    }

    SECTION("round trip to LedgerTxnRoot")
    {
        SECTION("with normal caching")
        {
            VirtualClock clock;
            auto app = createTestApplication(clock, getTestConfig());
            app->start();

            runTest(app->getLedgerTxnRoot());
        }

        SECTION("with no cache")
        {
            VirtualClock clock;
            auto cfg = getTestConfig();
            cfg.ENTRY_CACHE_SIZE = 0;
            cfg.BEST_OFFERS_CACHE_SIZE = 0;
            auto app = createTestApplication(clock, cfg);
            app->start();

            runTest(app->getLedgerTxnRoot());
        }
    }
}

TEST_CASE("LedgerTxn rollback and commit deactivate", "[ledgerstate]")
{
    VirtualClock clock;
    auto app = createTestApplication(clock, getTestConfig());
    app->start();

    auto& root = app->getLedgerTxnRoot();
    auto lh = root.getHeader();

    LedgerEntry le = LedgerTestUtils::generateValidLedgerEntry();
    LedgerKey key = LedgerEntryKey(le);

    auto checkDeactivate = [&](std::function<void(LedgerTxn & ls)> f) {
        SECTION("entry")
        {
            LedgerTxn ls(root, false);
            auto entry = ls.create(le);
            REQUIRE(entry);
            f(ls);
            REQUIRE(!entry);
        }

        SECTION("const entry")
        {
            LedgerTxn ls(root, false);
            ls.create(le);
            auto entry = ls.loadWithoutRecord(key);
            REQUIRE(entry);
            f(ls);
            REQUIRE(!entry);
        }

        SECTION("header")
        {
            LedgerTxn ls(root, false);
            auto header = ls.loadHeader();
            REQUIRE(header);
            f(ls);
            REQUIRE(!header);
        }
    };

    SECTION("commit")
    {
        checkDeactivate([](LedgerTxn& ls) { ls.commit(); });
    }

    SECTION("rollback")
    {
        checkDeactivate([](LedgerTxn& ls) { ls.rollback(); });
    }
}

TEST_CASE("LedgerTxn create", "[ledgerstate]")
{
    VirtualClock clock;
    auto app = createTestApplication(clock, getTestConfig());
    app->start();

    LedgerEntry le = LedgerTestUtils::generateValidLedgerEntry();
    le.lastModifiedLedgerSeq = 1;
    LedgerKey key = LedgerEntryKey(le);

    SECTION("fails with children")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        LedgerTxn ls2(ls1);
        REQUIRE_THROWS_AS(ls1.create(le), std::runtime_error);
    }

    SECTION("fails if sealed")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        ls1.getDelta();
        REQUIRE_THROWS_AS(ls1.create(le), std::runtime_error);
    }

    SECTION("when key does not exist")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        REQUIRE(ls1.create(le));
        validate(ls1,
                 {{key, {std::make_shared<LedgerEntry const>(le), nullptr}}});
    }

    SECTION("when key exists in self or parent")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        REQUIRE(ls1.create(le));
        REQUIRE_THROWS_AS(ls1.create(le), std::runtime_error);

        LedgerTxn ls2(ls1);
        REQUIRE_THROWS_AS(ls2.create(le), std::runtime_error);
        validate(ls2, {});
    }

    SECTION("when key exists in grandparent, erased in parent")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        REQUIRE(ls1.create(le));

        LedgerTxn ls2(ls1);
        REQUIRE_NOTHROW(ls2.erase(key));

        LedgerTxn ls3(ls2);
        REQUIRE(ls3.create(le));
        validate(ls3,
                 {{key, {std::make_shared<LedgerEntry const>(le), nullptr}}});
    }
}

TEST_CASE("LedgerTxn erase", "[ledgerstate]")
{
    VirtualClock clock;
    auto app = createTestApplication(clock, getTestConfig());
    app->start();

    LedgerEntry le = LedgerTestUtils::generateValidLedgerEntry();
    le.lastModifiedLedgerSeq = 1;
    LedgerKey key = LedgerEntryKey(le);

    SECTION("fails with children")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        REQUIRE(ls1.create(le));

        LedgerTxn ls2(ls1);
        REQUIRE_THROWS_AS(ls1.erase(key), std::runtime_error);
    }

    SECTION("fails if sealed")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        REQUIRE(ls1.create(le));
        ls1.getDelta();
        REQUIRE_THROWS_AS(ls1.erase(key), std::runtime_error);
    }

    SECTION("when key does not exist")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        REQUIRE_THROWS_AS(ls1.erase(key), std::runtime_error);
        validate(ls1, {});
    }

    SECTION("when key exists in parent")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        REQUIRE(ls1.create(le));

        LedgerTxn ls2(ls1);
        REQUIRE_NOTHROW(ls2.erase(key));
        validate(ls2,
                 {{key, {nullptr, std::make_shared<LedgerEntry const>(le)}}});
    }

    SECTION("when key exists in grandparent, erased in parent")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        REQUIRE(ls1.create(le));

        LedgerTxn ls2(ls1);
        REQUIRE_NOTHROW(ls2.erase(key));

        LedgerTxn ls3(ls2);
        REQUIRE_THROWS_AS(ls3.erase(key), std::runtime_error);
        validate(ls3, {});
    }
}

static void
applyLedgerTxnUpdates(
    AbstractLedgerTxn& ls,
    std::map<AccountID, std::pair<AccountID, int64_t>> const& updates)
{
    for (auto const& kv : updates)
    {
        auto lse = loadAccount(ls, kv.first);
        if (lse && kv.second.second > 0)
        {
            auto& ae = lse.current().data.account();
            ae.inflationDest.activate() = kv.second.first;
            ae.balance = kv.second.second;
        }
        else if (lse)
        {
            lse.erase();
        }
        else
        {
            REQUIRE(kv.second.second > 0);
            LedgerEntry acc;
            acc.lastModifiedLedgerSeq = ls.loadHeader().current().ledgerSeq;
            acc.data.type(ACCOUNT);

            auto& ae = acc.data.account();
            ae = LedgerTestUtils::generateValidAccountEntry();
            ae.accountID = kv.first;
            ae.inflationDest.activate() = kv.second.first;
            ae.balance = kv.second.second;

            ls.create(acc);
        }
    }
}

static void
testInflationWinners(
    AbstractLedgerTxnParent& lsParent, size_t maxWinners, int64_t minBalance,
    std::vector<std::tuple<AccountID, int64_t>> const& expected,
    std::vector<std::map<AccountID,
                         std::pair<AccountID, int64_t>>>::const_iterator begin,
    std::vector<std::map<AccountID, std::pair<AccountID, int64_t>>>::
        const_iterator const& end)
{
    REQUIRE(begin != end);
    LedgerTxn ls(lsParent);
    applyLedgerTxnUpdates(ls, *begin);

    if (++begin != end)
    {
        testInflationWinners(ls, maxWinners, minBalance, expected, begin, end);
    }
    else
    {
        auto winners = ls.queryInflationWinners(maxWinners, minBalance);
        auto expectedIter = expected.begin();
        auto iter = winners.begin();
        while (expectedIter != expected.end() && iter != winners.end())
        {
            REQUIRE(*expectedIter ==
                    std::make_tuple(iter->accountID, iter->votes));
            ++expectedIter;
            ++iter;
        }
        REQUIRE(expectedIter == expected.end());
        REQUIRE(iter == winners.end());
    }
}

static void
testInflationWinners(
    size_t maxWinners, int64_t minBalance,
    std::vector<std::tuple<AccountID, int64_t>> const& expected,
    std::vector<std::map<AccountID, std::pair<AccountID, int64_t>>> const&
        updates)
{
    REQUIRE(!updates.empty());

    auto testAtRoot = [&](Application& app) {
        {
            LedgerTxn ls1(app.getLedgerTxnRoot());
            applyLedgerTxnUpdates(ls1, *updates.cbegin());
            ls1.commit();
        }
        testInflationWinners(app.getLedgerTxnRoot(), maxWinners, minBalance,
                             expected, ++updates.cbegin(), updates.cend());
    };

    // first changes are in LedgerTxnRoot with cache
    if (updates.size() > 1)
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();
        testAtRoot(*app);
    }

    // first changes are in LedgerTxnRoot without cache
    if (updates.size() > 1)
    {
        VirtualClock clock;
        auto cfg = getTestConfig();
        cfg.ENTRY_CACHE_SIZE = 0;
        cfg.BEST_OFFERS_CACHE_SIZE = 0;
        auto app = createTestApplication(clock, cfg);
        app->start();
        testAtRoot(*app);
    }

    // first changes are in child of LedgerTxnRoot
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();

        testInflationWinners(app->getLedgerTxnRoot(), maxWinners, minBalance,
                             expected, updates.cbegin(), updates.cend());
    }
}

TEST_CASE("LedgerTxn queryInflationWinners", "[ledgerstate]")
{
    int64_t const QUERY_VOTE_MINIMUM = 1000000000;

    auto a1 = LedgerTestUtils::generateValidAccountEntry().accountID;
    auto a2 = LedgerTestUtils::generateValidAccountEntry().accountID;
    auto a3 = LedgerTestUtils::generateValidAccountEntry().accountID;
    auto a4 = LedgerTestUtils::generateValidAccountEntry().accountID;

    auto inflationSort =
        [](std::vector<std::tuple<AccountID, int64_t>> winners) {
            std::sort(winners.begin(), winners.end(),
                      [](auto const& lhs, auto const& rhs) {
                          if (std::get<1>(lhs) == std::get<1>(rhs))
                          {
                              return KeyUtils::toStrKey(std::get<0>(lhs)) >
                                     KeyUtils::toStrKey(std::get<0>(rhs));
                          }
                          return std::get<1>(lhs) > std::get<1>(rhs);
                      });
            return winners;
        };

    SECTION("fails with children")
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();

        LedgerTxn ls1(app->getLedgerTxnRoot());
        LedgerTxn ls2(ls1);
        REQUIRE_THROWS_AS(ls1.queryInflationWinners(1, 1), std::runtime_error);
    }

    SECTION("fails if sealed")
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();

        LedgerTxn ls1(app->getLedgerTxnRoot());
        ls1.getDelta();
        REQUIRE_THROWS_AS(ls1.queryInflationWinners(1, 1), std::runtime_error);
    }

    SECTION("empty parent")
    {
        SECTION("no voters")
        {
            testInflationWinners(1, QUERY_VOTE_MINIMUM, {}, {{}});
        }

        SECTION("one voter")
        {
            SECTION("below query minimum")
            {
                testInflationWinners(1, 1, {},
                                     {{{a1, {a2, QUERY_VOTE_MINIMUM - 1}}}});
            }

            SECTION("above query minimum")
            {
                testInflationWinners(1, 1, {{a2, QUERY_VOTE_MINIMUM}},
                                     {{{a1, {a2, QUERY_VOTE_MINIMUM}}}});
            }
        }

        SECTION("two voters")
        {
            SECTION("max one winner")
            {
                SECTION("same inflation destination")
                {
                    testInflationWinners(
                        1, QUERY_VOTE_MINIMUM,
                        {{a3, 2 * QUERY_VOTE_MINIMUM + 10}},
                        {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}},
                          {a2, {a3, QUERY_VOTE_MINIMUM + 7}}}});

                    SECTION("with total near min votes boundary")
                    {
                        testInflationWinners(
                            1, 2 * QUERY_VOTE_MINIMUM + 10,
                            {{a3, 2 * QUERY_VOTE_MINIMUM + 10}},
                            {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}},
                              {a2, {a3, QUERY_VOTE_MINIMUM + 7}}}});
                        testInflationWinners(
                            1, 2 * QUERY_VOTE_MINIMUM + 11, {},
                            {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}},
                              {a2, {a3, QUERY_VOTE_MINIMUM + 7}}}});
                    }
                }

                SECTION("different inflation destinations")
                {
                    testInflationWinners(
                        1, QUERY_VOTE_MINIMUM, {{a4, QUERY_VOTE_MINIMUM + 7}},
                        {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}},
                          {a2, {a4, QUERY_VOTE_MINIMUM + 7}}}});
                }
            }

            SECTION("max two winners")
            {
                SECTION("different inflation destinations")
                {
                    testInflationWinners(
                        2, QUERY_VOTE_MINIMUM,
                        inflationSort({{a3, QUERY_VOTE_MINIMUM + 3},
                                       {a4, QUERY_VOTE_MINIMUM + 7}}),
                        {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}},
                          {a2, {a4, QUERY_VOTE_MINIMUM + 7}}}});
                    testInflationWinners(
                        2, QUERY_VOTE_MINIMUM + 5,
                        {{a4, QUERY_VOTE_MINIMUM + 7}},
                        {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}},
                          {a2, {a4, QUERY_VOTE_MINIMUM + 7}}}});
                }
            }
        }
    }

    SECTION("one voter in parent")
    {
        SECTION("below query minimum")
        {
            testInflationWinners(1, 1, {},
                                 {{{a1, {a2, QUERY_VOTE_MINIMUM - 1}}}, {}});
        }

        SECTION("above query minimum")
        {
            testInflationWinners(1, 1, {{a2, QUERY_VOTE_MINIMUM}},
                                 {{{a1, {a2, QUERY_VOTE_MINIMUM}}}, {}});
        }

        SECTION("modified balance")
        {
            SECTION("from above to below query minimum")
            {
                testInflationWinners(1, 1, {},
                                     {{{a1, {a2, QUERY_VOTE_MINIMUM}}},
                                      {{a1, {a2, QUERY_VOTE_MINIMUM - 1}}}});
            }

            SECTION("from below to above query minimum")
            {
                testInflationWinners(1, 1, {{a2, QUERY_VOTE_MINIMUM}},
                                     {{{a1, {a2, QUERY_VOTE_MINIMUM - 1}}},
                                      {{a1, {a2, QUERY_VOTE_MINIMUM}}}});
            }
        }

        SECTION("modified inflation destination")
        {
            testInflationWinners(2, QUERY_VOTE_MINIMUM,
                                 {{a3, QUERY_VOTE_MINIMUM}},
                                 {{{a1, {a2, QUERY_VOTE_MINIMUM}}},
                                  {{a1, {a3, QUERY_VOTE_MINIMUM}}}});
        }

        SECTION("other voter")
        {
            SECTION("max one winner")
            {
                SECTION("same inflation destination")
                {
                    testInflationWinners(
                        1, QUERY_VOTE_MINIMUM,
                        {{a3, 2 * QUERY_VOTE_MINIMUM + 10}},
                        {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}}},
                         {{a2, {a3, QUERY_VOTE_MINIMUM + 7}}}});

                    SECTION("with total near min votes boundary")
                    {
                        testInflationWinners(
                            1, 2 * QUERY_VOTE_MINIMUM + 10,
                            {{a3, 2 * QUERY_VOTE_MINIMUM + 10}},
                            {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}}},
                             {{a2, {a3, QUERY_VOTE_MINIMUM + 7}}}});
                        testInflationWinners(
                            1, 2 * QUERY_VOTE_MINIMUM + 11, {},
                            {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}}},
                             {{a2, {a3, QUERY_VOTE_MINIMUM + 7}}}});
                    }
                }

                SECTION("different inflation destinations")
                {
                    testInflationWinners(
                        1, QUERY_VOTE_MINIMUM, {{a4, QUERY_VOTE_MINIMUM + 7}},
                        {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}}},
                         {{a2, {a4, QUERY_VOTE_MINIMUM + 7}}}});
                    testInflationWinners(
                        1, QUERY_VOTE_MINIMUM, {{a3, QUERY_VOTE_MINIMUM + 7}},
                        {{{a1, {a3, QUERY_VOTE_MINIMUM + 7}}},
                         {{a2, {a4, QUERY_VOTE_MINIMUM + 3}}}});
                }
            }

            SECTION("max two winners")
            {
                SECTION("different inflation destinations")
                {
                    testInflationWinners(
                        2, QUERY_VOTE_MINIMUM,
                        inflationSort({{a3, QUERY_VOTE_MINIMUM + 3},
                                       {a4, QUERY_VOTE_MINIMUM + 7}}),
                        {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}}},
                         {{a2, {a4, QUERY_VOTE_MINIMUM + 7}}}});
                    testInflationWinners(
                        2, QUERY_VOTE_MINIMUM + 5,
                        {{a4, QUERY_VOTE_MINIMUM + 7}},
                        {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}}},
                         {{a2, {a4, QUERY_VOTE_MINIMUM + 7}}}});
                    testInflationWinners(
                        2, QUERY_VOTE_MINIMUM + 5,
                        {{a3, QUERY_VOTE_MINIMUM + 7}},
                        {{{a1, {a3, QUERY_VOTE_MINIMUM + 7}}},
                         {{a2, {a4, QUERY_VOTE_MINIMUM + 3}}}});
                }
            }
        }
    }

    SECTION("two voters in parent")
    {
        SECTION("max one winner")
        {
            SECTION("same inflation destination")
            {
                testInflationWinners(1, QUERY_VOTE_MINIMUM,
                                     {{a3, 2 * QUERY_VOTE_MINIMUM + 10}},
                                     {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}},
                                       {a2, {a3, QUERY_VOTE_MINIMUM + 7}}},
                                      {}});

                SECTION("with total near min votes boundary")
                {
                    testInflationWinners(1, 2 * QUERY_VOTE_MINIMUM + 10,
                                         {{a3, 2 * QUERY_VOTE_MINIMUM + 10}},
                                         {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}},
                                           {a2, {a3, QUERY_VOTE_MINIMUM + 7}}},
                                          {}});
                    testInflationWinners(1, 2 * QUERY_VOTE_MINIMUM + 11, {},
                                         {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}},
                                           {a2, {a3, QUERY_VOTE_MINIMUM + 7}}},
                                          {}});
                }
            }

            SECTION("different inflation destinations")
            {
                testInflationWinners(1, QUERY_VOTE_MINIMUM,
                                     {{a4, QUERY_VOTE_MINIMUM + 7}},
                                     {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}},
                                       {a2, {a4, QUERY_VOTE_MINIMUM + 7}}},
                                      {}});
            }
        }

        SECTION("max two winners")
        {
            SECTION("different inflation destinations")
            {
                testInflationWinners(
                    2, QUERY_VOTE_MINIMUM,
                    inflationSort({{a3, QUERY_VOTE_MINIMUM + 3},
                                   {a4, QUERY_VOTE_MINIMUM + 7}}),
                    {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}},
                      {a2, {a4, QUERY_VOTE_MINIMUM + 7}}},
                     {}});
                testInflationWinners(2, QUERY_VOTE_MINIMUM + 5,
                                     {{a4, QUERY_VOTE_MINIMUM + 7}},
                                     {{{a1, {a3, QUERY_VOTE_MINIMUM + 3}},
                                       {a2, {a4, QUERY_VOTE_MINIMUM + 7}}},
                                      {}});
            }
        }
    }
}

TEST_CASE("LedgerTxn loadHeader", "[ledgerstate]")
{
    VirtualClock clock;
    auto app = createTestApplication(clock, getTestConfig());
    app->start();

    LedgerHeader lh = autocheck::generator<LedgerHeader>()(5);

    SECTION("fails with children")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        LedgerTxn ls2(ls1);
        REQUIRE_THROWS_AS(ls1.loadHeader(), std::runtime_error);
    }

    SECTION("fails if sealed")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        ls1.getDelta();
        REQUIRE_THROWS_AS(ls1.loadHeader(), std::runtime_error);
    }

    SECTION("fails if header already loaded")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        auto lhe = ls1.loadHeader();
        REQUIRE(lhe);
        REQUIRE_THROWS_AS(ls1.loadHeader(), std::runtime_error);
    }

    SECTION("check after update")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        auto lhPrev = ls1.loadHeader().current();
        ls1.loadHeader().current() = lh;

        auto delta = ls1.getDelta();
        REQUIRE(delta.header.current == lh);
        REQUIRE(delta.header.previous == lhPrev);
    }
}

TEST_CASE("LedgerTxn load", "[ledgerstate]")
{
    VirtualClock clock;
    auto app = createTestApplication(clock, getTestConfig());
    app->start();

    LedgerEntry le = LedgerTestUtils::generateValidLedgerEntry();
    le.lastModifiedLedgerSeq = 1;
    LedgerKey key = LedgerEntryKey(le);

    SECTION("fails with children")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        LedgerTxn ls2(ls1);
        REQUIRE_THROWS_AS(ls1.load(key), std::runtime_error);
    }

    SECTION("fails if sealed")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        ls1.getDelta();
        REQUIRE_THROWS_AS(ls1.load(key), std::runtime_error);
    }

    SECTION("when key does not exist")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        REQUIRE(!ls1.load(key));
        validate(ls1, {});
    }

    SECTION("when key exists in parent")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        REQUIRE(ls1.create(le));

        LedgerTxn ls2(ls1);
        REQUIRE(ls2.load(key));
        validate(ls2, {{key,
                        {std::make_shared<LedgerEntry const>(le),
                         std::make_shared<LedgerEntry const>(le)}}});
    }

    SECTION("when key exists in grandparent, erased in parent")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        REQUIRE(ls1.create(le));

        LedgerTxn ls2(ls1);
        REQUIRE_NOTHROW(ls2.erase(key));

        LedgerTxn ls3(ls2);
        REQUIRE(!ls3.load(key));
        validate(ls3, {});
    }
}

TEST_CASE("LedgerTxn loadWithoutRecord", "[ledgerstate]")
{
    VirtualClock clock;
    auto app = createTestApplication(clock, getTestConfig());
    app->start();

    LedgerEntry le = LedgerTestUtils::generateValidLedgerEntry();
    le.lastModifiedLedgerSeq = 1;
    LedgerKey key = LedgerEntryKey(le);

    SECTION("fails with children")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        LedgerTxn ls2(ls1);
        REQUIRE_THROWS_AS(ls1.loadWithoutRecord(key), std::runtime_error);
    }

    SECTION("fails if sealed")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        ls1.getDelta();
        REQUIRE_THROWS_AS(ls1.loadWithoutRecord(key), std::runtime_error);
    }

    SECTION("when key does not exist")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        REQUIRE(!ls1.loadWithoutRecord(key));
        validate(ls1, {});
    }

    SECTION("when key exists in parent")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        REQUIRE(ls1.create(le));

        LedgerTxn ls2(ls1);
        REQUIRE(ls2.loadWithoutRecord(key));
        validate(ls2, {});
    }

    SECTION("when key exists in grandparent, erased in parent")
    {
        LedgerTxn ls1(app->getLedgerTxnRoot());
        REQUIRE(ls1.create(le));

        LedgerTxn ls2(ls1);
        REQUIRE_NOTHROW(ls2.erase(key));

        LedgerTxn ls3(ls2);
        REQUIRE(!ls3.loadWithoutRecord(key));
        validate(ls3, {});
    }
}

static void
applyLedgerTxnUpdates(
    AbstractLedgerTxn& ls,
    std::map<std::pair<AccountID, uint64_t>,
             std::tuple<Asset, Asset, int64_t>> const& updates)
{
    for (auto const& kv : updates)
    {
        auto lse = loadOffer(ls, kv.first.first, kv.first.second);
        if (lse && std::get<2>(kv.second) > 0)
        {
            auto& oe = lse.current().data.offer();
            std::tie(oe.buying, oe.selling, oe.amount) = kv.second;
        }
        else if (lse)
        {
            lse.erase();
        }
        else
        {
            REQUIRE(std::get<2>(kv.second) > 0);
            LedgerEntry offer;
            offer.lastModifiedLedgerSeq = ls.loadHeader().current().ledgerSeq;
            offer.data.type(OFFER);

            auto& oe = offer.data.offer();
            oe = LedgerTestUtils::generateValidOfferEntry();
            std::tie(oe.sellerID, oe.offerID) = kv.first;
            std::tie(oe.buying, oe.selling, oe.amount) = kv.second;

            ls.create(offer);
        }
    }
}

static void
testAllOffers(
    AbstractLedgerTxnParent& lsParent,
    std::map<AccountID,
             std::vector<std::tuple<uint64_t, Asset, Asset, int64_t>>> const&
        expected,
    std::vector<std::map<std::pair<AccountID, uint64_t>,
                         std::tuple<Asset, Asset, int64_t>>>::const_iterator
        begin,
    std::vector<
        std::map<std::pair<AccountID, uint64_t>,
                 std::tuple<Asset, Asset, int64_t>>>::const_iterator const& end)
{
    REQUIRE(begin != end);
    LedgerTxn ls(lsParent);
    applyLedgerTxnUpdates(ls, *begin);

    if (++begin != end)
    {
        testAllOffers(ls, expected, begin, end);
    }
    else
    {
        auto offers = ls.loadAllOffers();
        auto expectedIter = expected.begin();
        auto iter = offers.begin();
        while (expectedIter != expected.end() && iter != offers.end())
        {
            REQUIRE(expectedIter->first == iter->first);

            auto expectedInner = expectedIter->second;
            auto const& inner = iter->second;

            REQUIRE(expectedInner.size() == inner.size());
            for (auto& innerCur : inner)
            {
                auto const& oe = innerCur.current().data.offer();
                auto d = std::make_tuple(oe.offerID, oe.buying, oe.selling,
                                         oe.amount);
                auto expectedInnerIter =
                    std::find(expectedInner.begin(), expectedInner.end(), d);
                REQUIRE(expectedInnerIter != expectedInner.end());
                expectedInner.erase(expectedInnerIter);
            }

            ++expectedIter;
            ++iter;
        }
        REQUIRE(expectedIter == expected.end());
        REQUIRE(iter == offers.end());
    }
}

static void
testAllOffers(
    std::map<AccountID,
             std::vector<std::tuple<uint64_t, Asset, Asset, int64_t>>> const&
        expected,
    std::vector<std::map<std::pair<AccountID, uint64_t>,
                         std::tuple<Asset, Asset, int64_t>>> const& updates)
{
    REQUIRE(!updates.empty());

    auto testAtRoot = [&](Application& app) {
        {
            LedgerTxn ls1(app.getLedgerTxnRoot());
            applyLedgerTxnUpdates(ls1, *updates.cbegin());
            ls1.commit();
        }
        testAllOffers(app.getLedgerTxnRoot(), expected, ++updates.cbegin(),
                      updates.cend());
    };

    // first changes are in LedgerTxnRoot with cache
    if (updates.size() > 1)
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();
        testAtRoot(*app);
    }

    // first changes are in LedgerTxnRoot without cache
    if (updates.size() > 1)
    {
        VirtualClock clock;
        auto cfg = getTestConfig();
        cfg.ENTRY_CACHE_SIZE = 0;
        cfg.BEST_OFFERS_CACHE_SIZE = 0;
        auto app = createTestApplication(clock, cfg);
        app->start();
        testAtRoot(*app);
    }

    // first changes are in child of LedgerTxnRoot
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();

        testAllOffers(app->getLedgerTxnRoot(), expected, updates.cbegin(),
                      updates.cend());
    }
}

TEST_CASE("LedgerTxn loadAllOffers", "[ledgerstate]")
{
    auto a1 = LedgerTestUtils::generateValidAccountEntry().accountID;
    auto a2 = LedgerTestUtils::generateValidAccountEntry().accountID;

    Asset buying = LedgerTestUtils::generateValidOfferEntry().buying;
    Asset selling = LedgerTestUtils::generateValidOfferEntry().selling;

    SECTION("fails with children")
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();

        LedgerTxn ls1(app->getLedgerTxnRoot());
        LedgerTxn ls2(ls1);
        REQUIRE_THROWS_AS(ls1.loadAllOffers(), std::runtime_error);
    }

    SECTION("fails if sealed")
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();

        LedgerTxn ls1(app->getLedgerTxnRoot());
        ls1.getDelta();
        REQUIRE_THROWS_AS(ls1.loadAllOffers(), std::runtime_error);
    }

    SECTION("empty parent")
    {
        SECTION("no offers")
        {
            testAllOffers({}, {{}});
        }

        SECTION("two offers")
        {
            SECTION("same account")
            {
                testAllOffers(
                    {{a1, {{1, buying, selling, 1}, {2, buying, selling, 1}}}},
                    {{{{a1, 1}, {buying, selling, 1}},
                      {{a1, 2}, {buying, selling, 1}}}});
            }

            SECTION("different accounts")
            {
                testAllOffers({{a1, {{1, buying, selling, 1}}},
                               {a2, {{2, buying, selling, 1}}}},
                              {{{{a1, 1}, {buying, selling, 1}},
                                {{a2, 2}, {buying, selling, 1}}}});
            }
        }
    }

    SECTION("one offer in parent")
    {
        SECTION("erased in child")
        {
            testAllOffers({}, {{{{a1, 1}, {buying, selling, 1}}},
                               {{{a1, 1}, {buying, selling, 0}}}});
        }

        SECTION("modified assets in child")
        {
            testAllOffers({{a1, {{1, selling, buying, 1}}}},
                          {{{{a1, 1}, {buying, selling, 1}}},
                           {{{a1, 1}, {selling, buying, 1}}}});
        }

        SECTION("modified amount in child")
        {
            testAllOffers({{a1, {{1, buying, selling, 7}}}},
                          {{{{a1, 1}, {buying, selling, 1}}},
                           {{{a1, 1}, {buying, selling, 7}}}});
        }

        SECTION("other offer in child")
        {
            SECTION("same account")
            {
                testAllOffers(
                    {{a1, {{1, buying, selling, 1}, {2, buying, selling, 1}}}},
                    {{{{a1, 1}, {buying, selling, 1}}},
                     {{{a1, 2}, {buying, selling, 1}}}});
                testAllOffers(
                    {{a1, {{1, buying, selling, 1}, {2, buying, selling, 1}}}},
                    {{{{a1, 2}, {buying, selling, 1}}},
                     {{{a1, 1}, {buying, selling, 1}}}});
            }

            SECTION("different accounts")
            {
                testAllOffers({{a1, {{1, buying, selling, 1}}},
                               {a2, {{2, buying, selling, 1}}}},
                              {{{{a1, 1}, {buying, selling, 1}}},
                               {{{a2, 2}, {buying, selling, 1}}}});
            }
        }
    }

    SECTION("two offers in parent")
    {
        SECTION("same account")
        {
            testAllOffers(
                {{a1, {{1, buying, selling, 1}, {2, buying, selling, 1}}}},
                {{{{a1, 1}, {buying, selling, 1}},
                  {{a1, 2}, {buying, selling, 1}}},
                 {}});
        }

        SECTION("different accounts")
        {
            testAllOffers({{a1, {{1, buying, selling, 1}}},
                           {a2, {{2, buying, selling, 1}}}},
                          {{{{a1, 1}, {buying, selling, 1}},
                            {{a2, 2}, {buying, selling, 1}}},
                           {}});
        }
    }
}

static void
applyLedgerTxnUpdates(
    AbstractLedgerTxn& ls,
    std::map<std::pair<AccountID, uint64_t>,
             std::tuple<Asset, Asset, Price, int64_t>> const& updates)
{
    for (auto const& kv : updates)
    {
        auto lse = loadOffer(ls, kv.first.first, kv.first.second);
        if (lse && std::get<3>(kv.second) > 0)
        {
            auto& oe = lse.current().data.offer();
            std::tie(oe.buying, oe.selling, oe.price, oe.amount) = kv.second;
        }
        else if (lse)
        {
            lse.erase();
        }
        else
        {
            REQUIRE(std::get<3>(kv.second) > 0);
            LedgerEntry offer;
            offer.lastModifiedLedgerSeq = ls.loadHeader().current().ledgerSeq;
            offer.data.type(OFFER);

            auto& oe = offer.data.offer();
            oe = LedgerTestUtils::generateValidOfferEntry();
            std::tie(oe.sellerID, oe.offerID) = kv.first;
            std::tie(oe.buying, oe.selling, oe.price, oe.amount) = kv.second;

            ls.create(offer);
        }
    }
}

static void
testBestOffer(
    AbstractLedgerTxnParent& lsParent, Asset const& buying,
    Asset const& selling,
    std::vector<std::tuple<uint64_t, Asset, Asset, Price, int64_t>> const&
        expected,
    std::vector<std::map<std::pair<AccountID, uint64_t>,
                         std::tuple<Asset, Asset, Price, int64_t>>>::
        const_iterator begin,
    std::vector<std::map<std::pair<AccountID, uint64_t>,
                         std::tuple<Asset, Asset, Price, int64_t>>>::
        const_iterator const& end)
{
    REQUIRE(begin != end);
    LedgerTxn ls(lsParent);
    applyLedgerTxnUpdates(ls, *begin);

    if (++begin != end)
    {
        testBestOffer(ls, buying, selling, expected, begin, end);
    }
    else
    {
        auto offer = ls.loadBestOffer(buying, selling);
        if (offer)
        {
            auto const& oe = offer.current().data.offer();
            REQUIRE(expected.size() == 1);
            REQUIRE(expected.front() == std::make_tuple(oe.offerID, oe.buying,
                                                        oe.selling, oe.price,
                                                        oe.amount));
        }
        else
        {
            REQUIRE(expected.empty());
        }
    }
}

static void
testBestOffer(
    Asset const& buying, Asset const& selling,
    std::vector<std::tuple<uint64_t, Asset, Asset, Price, int64_t>> const&
        expected,
    std::vector<std::map<std::pair<AccountID, uint64_t>,
                         std::tuple<Asset, Asset, Price, int64_t>>>
        updates)
{
    REQUIRE(!updates.empty());

    auto testAtRoot = [&](Application& app) {
        {
            LedgerTxn ls1(app.getLedgerTxnRoot());
            applyLedgerTxnUpdates(ls1, *updates.cbegin());
            ls1.commit();
        }
        testBestOffer(app.getLedgerTxnRoot(), buying, selling, expected,
                      ++updates.cbegin(), updates.cend());
    };

    // first changes are in LedgerTxnRoot with cache
    if (updates.size() > 1)
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();
        testAtRoot(*app);
    }

    // first changes are in LedgerTxnRoot without cache
    if (updates.size() > 1)
    {
        VirtualClock clock;
        auto cfg = getTestConfig();
        cfg.ENTRY_CACHE_SIZE = 0;
        cfg.BEST_OFFERS_CACHE_SIZE = 0;
        auto app = createTestApplication(clock, cfg);
        app->start();
        testAtRoot(*app);
    }

    // first changes are in child of LedgerTxnRoot
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();

        testBestOffer(app->getLedgerTxnRoot(), buying, selling, expected,
                      updates.cbegin(), updates.cend());
    }
}

TEST_CASE("LedgerTxn loadBestOffer", "[ledgerstate]")
{
    auto a1 = LedgerTestUtils::generateValidAccountEntry().accountID;
    auto a2 = LedgerTestUtils::generateValidAccountEntry().accountID;

    Asset buying = LedgerTestUtils::generateValidOfferEntry().buying;
    Asset selling = LedgerTestUtils::generateValidOfferEntry().selling;
    REQUIRE(!(buying == selling));

    SECTION("fails with children")
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();

        LedgerTxn ls1(app->getLedgerTxnRoot());
        LedgerTxn ls2(ls1);
        REQUIRE_THROWS_AS(ls1.loadBestOffer(buying, selling),
                          std::runtime_error);
    }

    SECTION("fails if sealed")
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();

        LedgerTxn ls1(app->getLedgerTxnRoot());
        ls1.getDelta();
        REQUIRE_THROWS_AS(ls1.loadBestOffer(buying, selling),
                          std::runtime_error);
    }

    SECTION("empty parent")
    {
        SECTION("no offers")
        {
            testBestOffer(buying, selling, {}, {{}});
        }

        SECTION("two offers")
        {
            SECTION("same assets")
            {
                SECTION("same price")
                {
                    testBestOffer(
                        buying, selling, {{1, buying, selling, Price{1, 1}, 1}},
                        {{{{a1, 1}, {buying, selling, Price{1, 1}, 1}},
                          {{a1, 2}, {buying, selling, Price{1, 1}, 1}}}});
                }

                SECTION("different price")
                {
                    testBestOffer(
                        buying, selling, {{2, buying, selling, Price{1, 1}, 1}},
                        {{{{a1, 1}, {buying, selling, Price{2, 1}, 1}},
                          {{a1, 2}, {buying, selling, Price{1, 1}, 1}}}});
                    testBestOffer(
                        buying, selling, {{1, buying, selling, Price{1, 1}, 1}},
                        {{{{a1, 1}, {buying, selling, Price{1, 1}, 1}},
                          {{a1, 2}, {buying, selling, Price{2, 1}, 1}}}});
                }
            }

            SECTION("different assets")
            {
                testBestOffer(buying, selling,
                              {{1, buying, selling, Price{1, 1}, 1}},
                              {{{{a1, 1}, {buying, selling, Price{1, 1}, 1}},
                                {{a1, 2}, {selling, buying, Price{1, 1}, 1}}}});
                testBestOffer(buying, selling,
                              {{2, buying, selling, Price{1, 1}, 1}},
                              {{{{a1, 1}, {selling, buying, Price{1, 1}, 1}},
                                {{a1, 2}, {buying, selling, Price{1, 1}, 1}}}});
            }
        }
    }

    SECTION("one offer in parent")
    {
        SECTION("erased in child")
        {
            testBestOffer(buying, selling, {},
                          {{{{a1, 1}, {buying, selling, Price{1, 1}, 1}}},
                           {{{a1, 1}, {buying, selling, Price{1, 1}, 0}}}});
        }

        SECTION("modified assets in child")
        {
            testBestOffer(buying, selling, {},
                          {{{{a1, 1}, {buying, selling, Price{1, 1}, 1}}},
                           {{{a1, 1}, {selling, buying, Price{1, 1}, 1}}}});
            testBestOffer(buying, selling,
                          {{1, buying, selling, Price{1, 1}, 1}},
                          {{{{a1, 1}, {selling, buying, Price{1, 1}, 1}}},
                           {{{a1, 1}, {buying, selling, Price{1, 1}, 1}}}});
        }

        SECTION("modified price and amount in child")
        {
            testBestOffer(buying, selling,
                          {{1, buying, selling, Price{2, 1}, 7}},
                          {{{{a1, 1}, {buying, selling, Price{1, 1}, 1}}},
                           {{{a1, 1}, {buying, selling, Price{2, 1}, 7}}}});
        }

        SECTION("other offer in child")
        {
            testBestOffer(buying, selling,
                          {{1, buying, selling, Price{1, 1}, 1}},
                          {{{{a1, 1}, {buying, selling, Price{1, 1}, 1}}},
                           {{{a1, 2}, {buying, selling, Price{1, 1}, 1}}}});
            testBestOffer(buying, selling,
                          {{1, buying, selling, Price{1, 1}, 1}},
                          {{{{a1, 2}, {buying, selling, Price{1, 1}, 1}}},
                           {{{a1, 1}, {buying, selling, Price{1, 1}, 1}}}});

            testBestOffer(buying, selling,
                          {{2, buying, selling, Price{1, 2}, 1}},
                          {{{{a1, 1}, {buying, selling, Price{1, 1}, 1}}},
                           {{{a1, 2}, {buying, selling, Price{1, 2}, 1}}}});
            testBestOffer(buying, selling,
                          {{2, buying, selling, Price{1, 2}, 1}},
                          {{{{a1, 2}, {buying, selling, Price{1, 2}, 1}}},
                           {{{a1, 1}, {buying, selling, Price{1, 1}, 1}}}});
        }
    }

    SECTION("two offers in parent")
    {
        SECTION("erased in child")
        {
            testBestOffer(buying, selling,
                          {{2, buying, selling, Price{1, 1}, 1}},
                          {{{{a1, 1}, {buying, selling, Price{1, 1}, 1}},
                            {{a1, 2}, {buying, selling, Price{1, 1}, 1}}},
                           {{{a1, 1}, {buying, selling, Price{1, 1}, 0}}}});
        }

        SECTION("modified assets in child")
        {
            testBestOffer(buying, selling,
                          {{2, buying, selling, Price{1, 1}, 1}},
                          {{{{a1, 1}, {buying, selling, Price{1, 1}, 1}},
                            {{a1, 2}, {buying, selling, Price{1, 1}, 1}}},
                           {{{a1, 1}, {selling, buying, Price{1, 1}, 0}}}});
        }
    }
}

static void
testOffersByAccountAndAsset(
    AbstractLedgerTxnParent& lsParent, AccountID const& accountID,
    Asset const& asset,
    std::vector<std::tuple<uint64_t, Asset, Asset, int64_t>> const& expected,
    std::vector<std::map<std::pair<AccountID, uint64_t>,
                         std::tuple<Asset, Asset, int64_t>>>::const_iterator
        begin,
    std::vector<
        std::map<std::pair<AccountID, uint64_t>,
                 std::tuple<Asset, Asset, int64_t>>>::const_iterator const& end)
{
    REQUIRE(begin != end);
    LedgerTxn ls(lsParent);
    applyLedgerTxnUpdates(ls, *begin);

    if (++begin != end)
    {
        testOffersByAccountAndAsset(ls, accountID, asset, expected, begin, end);
    }
    else
    {
        auto offers = ls.loadOffersByAccountAndAsset(accountID, asset);
        REQUIRE(expected.size() == offers.size());
        auto expected2 = expected;

        for (auto& curoff : offers)
        {
            auto const& oe = curoff.current().data.offer();
            auto expo =
                std::make_tuple(oe.offerID, oe.buying, oe.selling, oe.amount);
            auto it = std::find(expected2.begin(), expected2.end(), expo);
            REQUIRE(it != expected2.end());
            expected2.erase(it);
        }
    }
}

static void
testOffersByAccountAndAsset(
    AccountID const& accountID, Asset const& asset,
    std::vector<std::tuple<uint64_t, Asset, Asset, int64_t>> const& expected,
    std::vector<std::map<std::pair<AccountID, uint64_t>,
                         std::tuple<Asset, Asset, int64_t>>>
        updates)
{
    REQUIRE(!updates.empty());

    auto testAtRoot = [&](Application& app) {
        {
            LedgerTxn ls1(app.getLedgerTxnRoot());
            applyLedgerTxnUpdates(ls1, *updates.cbegin());
            ls1.commit();
        }
        testOffersByAccountAndAsset(app.getLedgerTxnRoot(), accountID, asset,
                                    expected, ++updates.cbegin(),
                                    updates.cend());
    };

    // first changes are in LedgerTxnRoot with cache
    if (updates.size() > 1)
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();
        testAtRoot(*app);
    }

    // first changes are in LedgerTxnRoot without cache
    if (updates.size() > 1)
    {
        VirtualClock clock;
        auto cfg = getTestConfig();
        cfg.ENTRY_CACHE_SIZE = 0;
        cfg.BEST_OFFERS_CACHE_SIZE = 0;
        auto app = createTestApplication(clock, cfg);
        app->start();
        testAtRoot(*app);
    }

    // first changes are in child of LedgerTxnRoot
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();

        testOffersByAccountAndAsset(app->getLedgerTxnRoot(), accountID, asset,
                                    expected, updates.cbegin(), updates.cend());
    }
}

TEST_CASE("LedgerTxn loadOffersByAccountAndAsset", "[ledgerstate]")
{
    auto a1 = LedgerTestUtils::generateValidAccountEntry().accountID;
    auto a2 = LedgerTestUtils::generateValidAccountEntry().accountID;

    Asset native(ASSET_TYPE_NATIVE);
    Asset buying = LedgerTestUtils::generateValidOfferEntry().buying;
    Asset selling = LedgerTestUtils::generateValidOfferEntry().selling;
    REQUIRE(buying.type() != ASSET_TYPE_NATIVE);
    REQUIRE(selling.type() != ASSET_TYPE_NATIVE);
    REQUIRE(!(buying == selling));

    SECTION("fails with children")
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();

        LedgerTxn ls1(app->getLedgerTxnRoot());
        LedgerTxn ls2(ls1);
        REQUIRE_THROWS_AS(ls1.loadOffersByAccountAndAsset(a1, buying),
                          std::runtime_error);
    }

    SECTION("fails if sealed")
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, getTestConfig());
        app->start();

        LedgerTxn ls1(app->getLedgerTxnRoot());
        ls1.getDelta();
        REQUIRE_THROWS_AS(ls1.loadOffersByAccountAndAsset(a1, buying),
                          std::runtime_error);
    }

    SECTION("empty parent")
    {
        SECTION("no offers")
        {
            testOffersByAccountAndAsset(a1, buying, {}, {{}});
        }

        SECTION("two offers")
        {
            testOffersByAccountAndAsset(
                a1, buying, {{1, buying, native, 1}, {2, buying, native, 1}},
                {{{{a1, 1}, {buying, native, 1}},
                  {{a1, 2}, {buying, native, 1}}}});
        }
    }

    SECTION("one offer in parent")
    {
        SECTION("erased in child")
        {
            testOffersByAccountAndAsset(a1, buying, {},
                                        {{{{a1, 1}, {buying, native, 1}}},
                                         {{{a1, 1}, {buying, native, 0}}}});
            testOffersByAccountAndAsset(a1, buying, {},
                                        {{{{a1, 1}, {native, buying, 1}}},
                                         {{{a1, 1}, {native, buying, 0}}}});
        }

        SECTION("modified assets in child")
        {
            testOffersByAccountAndAsset(a1, buying, {},
                                        {{{{a1, 1}, {buying, native, 1}}},
                                         {{{a1, 1}, {selling, native, 1}}}});
            testOffersByAccountAndAsset(a1, buying, {{1, buying, native, 1}},
                                        {{{{a1, 1}, {selling, native, 1}}},
                                         {{{a1, 1}, {buying, native, 1}}}});

            testOffersByAccountAndAsset(a1, buying, {},
                                        {{{{a1, 1}, {native, buying, 1}}},
                                         {{{a1, 1}, {native, selling, 1}}}});
            testOffersByAccountAndAsset(a1, buying, {{1, native, buying, 1}},
                                        {{{{a1, 1}, {native, selling, 1}}},
                                         {{{a1, 1}, {native, buying, 1}}}});

            testOffersByAccountAndAsset(a1, buying, {{1, native, buying, 1}},
                                        {{{{a1, 1}, {buying, native, 1}}},
                                         {{{a1, 1}, {native, buying, 1}}}});
            testOffersByAccountAndAsset(a1, buying, {{1, buying, native, 1}},
                                        {{{{a1, 1}, {native, buying, 1}}},
                                         {{{a1, 1}, {buying, native, 1}}}});
        }

        SECTION("modified amount in child")
        {
            testOffersByAccountAndAsset(a1, buying, {{1, buying, native, 7}},
                                        {{{{a1, 1}, {buying, native, 1}}},
                                         {{{a1, 1}, {buying, native, 7}}}});
        }

        SECTION("other offer in child")
        {
            testOffersByAccountAndAsset(
                a1, buying, {{1, buying, native, 1}, {2, buying, native, 1}},
                {{{{a1, 1}, {buying, native, 1}}},
                 {{{a1, 2}, {buying, native, 1}}}});
        }
    }

    SECTION("two offers in parent")
    {
        testOffersByAccountAndAsset(
            a1, buying, {{1, buying, native, 1}, {2, buying, native, 1}},
            {{{{a1, 1}, {buying, native, 1}}, {{a1, 2}, {buying, native, 1}}},
             {}});
        testOffersByAccountAndAsset(
            a1, buying, {{1, buying, native, 1}, {2, native, buying, 1}},
            {{{{a1, 1}, {buying, native, 1}}, {{a1, 2}, {native, buying, 1}}},
             {}});
    }
}

TEST_CASE("LedgerTxn unsealHeader", "[ledgerstate]")
{
    VirtualClock clock;
    auto app = createTestApplication(clock, getTestConfig());
    app->start();

    auto doNothing = [](LedgerHeader&) {};

    SECTION("fails if not sealed")
    {
        LedgerTxn ls(app->getLedgerTxnRoot());
        REQUIRE_THROWS_AS(ls.unsealHeader(doNothing), std::runtime_error);
    }

    SECTION("fails if header is active")
    {
        LedgerTxn ls(app->getLedgerTxnRoot());
        ls.getLiveEntries();
        ls.unsealHeader([&ls, &doNothing](LedgerHeader&) {
            REQUIRE_THROWS_AS(ls.unsealHeader(doNothing), std::runtime_error);
        });
    }

    SECTION("deactivates header on completion")
    {
        LedgerTxn ls(app->getLedgerTxnRoot());
        ls.getLiveEntries();
        REQUIRE_NOTHROW(ls.unsealHeader(doNothing));
        REQUIRE_NOTHROW(ls.unsealHeader(doNothing));
    }
}

TEST_CASE("LedgerTxnEntry and LedgerTxnHeader move assignment",
          "[ledgerstate]")
{
    VirtualClock clock;
    auto app = createTestApplication(clock, getTestConfig());
    app->start();

    auto& root = app->getLedgerTxnRoot();
    auto lh = root.getHeader();

    LedgerEntry le1 = LedgerTestUtils::generateValidLedgerEntry();
    LedgerKey key1 = LedgerEntryKey(le1);
    LedgerEntry le2 = LedgerTestUtils::generateValidLedgerEntry();
    LedgerKey key2 = LedgerEntryKey(le2);

    SECTION("assign self")
    {
        SECTION("entry")
        {
            LedgerTxn ls(root, false);
            auto entry1 = ls.create(le1);
            // Avoid warning for explicit move-to-self
            LedgerTxnEntry& entryRef = entry1;
            entry1 = std::move(entryRef);
            REQUIRE(entry1.current() == le1);
            REQUIRE_THROWS_AS(ls.load(key1), std::runtime_error);
            REQUIRE_THROWS_AS(ls.loadWithoutRecord(key1), std::runtime_error);
        }

        SECTION("const entry")
        {
            LedgerTxn ls(root, false);
            ls.create(le1);
            auto entry1 = ls.loadWithoutRecord(key1);
            // Avoid warning for explicit move-to-self
            ConstLedgerTxnEntry& entryRef = entry1;
            entry1 = std::move(entryRef);
            REQUIRE(entry1.current() == le1);
            REQUIRE_THROWS_AS(ls.load(key1), std::runtime_error);
            REQUIRE_THROWS_AS(ls.loadWithoutRecord(key1), std::runtime_error);
        }

        SECTION("header")
        {
            LedgerTxn ls(root, false);
            auto header = ls.loadHeader();
            // Avoid warning for explicit move-to-self
            LedgerTxnHeader& headerRef = header;
            header = std::move(headerRef);
            REQUIRE(header.current() == lh);
            REQUIRE_THROWS_AS(ls.loadHeader(), std::runtime_error);
        }
    }

    SECTION("assign other")
    {
        SECTION("entry")
        {
            LedgerTxn ls(root, false);
            auto entry1 = ls.create(le1);
            auto entry2 = ls.create(le2);
            entry1 = std::move(entry2);
            REQUIRE(entry1.current() == le2);
            REQUIRE_THROWS_AS(ls.load(key2), std::runtime_error);
            REQUIRE(ls.load(key1).current() == le1);
            REQUIRE(ls.loadWithoutRecord(key1).current() == le1);
        }

        SECTION("const entry")
        {
            LedgerTxn ls(root, false);
            ls.create(le1);
            ls.create(le2);
            auto entry1 = ls.loadWithoutRecord(key1);
            auto entry2 = ls.loadWithoutRecord(key2);
            entry1 = std::move(entry2);
            REQUIRE(entry1.current() == le2);
            REQUIRE_THROWS_AS(ls.load(key2), std::runtime_error);
            REQUIRE(ls.load(key1).current() == le1);
            REQUIRE(ls.loadWithoutRecord(key1).current() == le1);
        }

        SECTION("header")
        {
            LedgerTxn ls(root, false);
            auto header1 = ls.loadHeader();
            LedgerTxnHeader header2 = std::move(header1);
            REQUIRE(header2.current() == lh);
            REQUIRE_THROWS_AS(ls.loadHeader(), std::runtime_error);
        }
    }
}
