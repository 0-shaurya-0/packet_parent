"""Service presentation, conservative classification and catalog migration tests."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from catalog import CATALOG_VERSION, classify
from rules import active
from service import Store
from test_packetparent import BASE, DAY


def observation(domain, timestamp, device='192.168.1.3', evidence='TLS server name', remote='8.8.4.4'):
    """Build unique parser-shaped metadata without capturing or dropping any traffic."""
    identity = f'{domain}|{timestamp}|{device}|{evidence}|{remote}'
    return dict(fingerprint=hashlib.sha256(identity.encode()).hexdigest(),
                timestamp=timestamp, device_ip=device, source_ip=device, remote_ip=remote,
                domain=domain, protocol='UDP' if evidence == 'DNS query' else 'TCP',
                evidence=evidence, active=int(evidence != 'DNS query'), bytes=100)


def session_rows():
    """Mimic video assets, Office login, telemetry, AI, Search, IPs and DNS lookups."""
    domains = [
        'rr7---sn-test.googlevideo.com', 'i.ytimg.com', 'yt3.ggpht.com',
        'ad.doubleclick.net', 'youtube.com', 'teams.cloud.microsoft',
        'onecdn.static.microsoft', 'graph.microsoft.com',
        'browser.events.data.microsoft.com', 'monitor.azure.com',
        'chatgpt.com', 'www.google.com',
    ]
    rows = []
    for index, domain in enumerate(domains):
        for offset in (0, 20):
            rows.append(observation(domain, BASE + 3600 + index * 5 + offset))
    for index, remote in enumerate(('8.8.4.4', '1.1.1.1', '9.9.9.9'), start=12):
        for offset in (0, 20):
            rows.append(observation('', BASE + 3600 + index * 5 + offset,
                                    evidence='IP connection', remote=remote))
    for index, domain in enumerate(('youtube.com', 'teams.cloud.microsoft', 'lookup-only.example')):
        rows.append(observation(domain, BASE + 3590 + index, evidence='DNS query'))
    return sorted(rows, key=lambda row: row['timestamp'])


def import_rows(store, rows, name='scenario', monitored=None):
    """Exercise real ingest and alert logic with deterministic parser output."""
    with patch('service.parse_capture', return_value=(rows, {'packets': len(rows), 'observations': len(rows)})):
        return store.import_capture(name.encode(), name + '.pcap', monitored=monitored)


def rule(kind, target='', name=None):
    """Build an enabled rule with an overnight test-friendly permitted window."""
    return dict(name=name or kind, kind=kind, target=target,
                start='07:00' if kind == 'hours' else '',
                end='22:00' if kind == 'hours' else '',
                minutes=1, device_ip='', enabled=1)


class CatalogTests(unittest.TestCase):
    def test_video_assets_and_boundary(self):
        """YouTube CDN hosts stay visible, while suffix lookalikes never match."""
        for domain in ('youtube.com', 'youtu.be', 'rr7---sn-test.googlevideo.com', 'i.ytimg.com', 'yt3.ggpht.com'):
            self.assertEqual(classify(domain), dict(service='YouTube', category='Entertainment', noise=None))
        self.assertIsNone(classify('notyoutube.com')['service'])
        self.assertIsNone(classify('youtube.com.evil.example')['service'])
        self.assertIsNone(classify('unknown.example')['noise'])
        self.assertIsNone(classify('unknown.example')['service'])
        self.assertEqual(classify('YOUTUBE.COM.')['service'], 'YouTube')

    def test_noise_ai_office_and_specific_google_hosts(self):
        """Known background is positive matched; shared Google APIs remain visible."""
        self.assertEqual(classify('ad.doubleclick.net')['noise'], 'ads')
        self.assertEqual(classify('ogads-pa.clients6.google.com')['noise'], 'ads')
        self.assertIsNone(classify('docs.clients6.google.com')['noise'])
        self.assertIsNone(classify('docs.clients6.google.com')['service'])
        self.assertIsNone(classify('notdoubleclick.net')['noise'])
        self.assertEqual(classify('chatgpt.com'), dict(service='ChatGPT', category='AI', noise=None))
        self.assertEqual(classify('api.openai.com')['category'], 'AI')
        for domain in ('teams.microsoft.com', 'teams.cloud.microsoft', 'office.com', 'office.net',
                       'officeapps.live.com', 'onecdn.static.microsoft', 'tenant.sharepoint.com',
                       'graph.microsoft.com', 'login.live.com', 'login.microsoftonline.com', 'live.com'):
            self.assertEqual(classify(domain)['service'], 'Microsoft Teams & Office')
            self.assertEqual(classify(domain)['category'], 'Productivity')
        for domain in ('google.com', 'www.google.com'):
            self.assertEqual(classify(domain)['service'], 'Google Search')
        for domain in ('browser.events.data.microsoft.com', 'monitor.azure.com', 'vortex.data.microsoft.com'):
            self.assertEqual(classify(domain)['noise'], 'telemetry')
        for domain in ('windowsupdate.com', 'update.microsoft.com', 'time.windows.com',
                       'pool.ntp.org', 'msftconnecttest.com', 'connectivitycheck.gstatic.com'):
            self.assertEqual(classify(domain)['noise'], 'system')


class ServiceTests(unittest.TestCase):
    def setUp(self):
        """Give each regression an isolated empty database."""
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'db.sqlite3'
        self.store = Store(self.path)

    def tearDown(self):
        """Remove temporary metadata after all SQLite connections close."""
        self.temp.cleanup()

    def test_realistic_session_rows_and_background_toggle(self):
        """Eighteen raw entries collapse to five services without removing data."""
        rows = session_rows()
        import_rows(self.store, rows)
        view = self.store.snapshot(DAY.isoformat())
        self.assertEqual(len(view['activity']), 18)
        self.assertEqual(len(view['services']), 5)
        by_name = {entry['service']: entry for entry in view['services']}
        self.assertEqual(set(by_name), {'YouTube', 'Microsoft Teams & Office', 'ChatGPT',
                                       'Google Search', 'Unidentified connections'})
        self.assertEqual(by_name['YouTube']['active_seconds'], 40)
        self.assertEqual(by_name['Microsoft Teams & Office']['active_seconds'], 30)
        self.assertEqual(by_name['ChatGPT']['active_seconds'], 20)
        self.assertEqual(view['summary']['seconds'], 90)
        self.assertGreater(sum(entry['active_seconds'] for entry in view['services']), 90)
        self.assertEqual(view['categories'], dict(Entertainment=40, Productivity=50, AI=20, Unknown=30))
        ips = by_name['Unidentified connections']['domains']
        self.assertEqual({entry['domain'] for entry in ips}, {'8.8.4.4', '1.1.1.1', '9.9.9.9'})
        self.assertTrue(all('DNS query' not in detail['evidence']
                            for entry in view['services'] for detail in entry['domains']))
        with_background = self.store.snapshot(DAY.isoformat(), include_background=True)
        self.assertEqual(len(with_background['services']), 6)
        background = next(entry for entry in with_background['services'] if entry['service'].startswith('Background traffic'))
        self.assertEqual(background['packets'], 6)
        self.assertEqual(background['active_seconds'], 0)
        self.assertEqual({entry['domain'] for entry in background['domains']},
                         {'ad.doubleclick.net', 'browser.events.data.microsoft.com', 'monitor.azure.com'})
        self.assertEqual(view['activity'], with_background['activity'])
        self.assertEqual(view['categories'], with_background['categories'])
        self.assertEqual(view['summary']['observations'], len(rows))
        self.assertEqual(sum(entry['count'] for entry in view['activity']), len(rows))
        self.assertTrue(all('service' in entry and 'noise' in entry for entry in view['activity']))
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT SUM(packets) FROM events').fetchone()[0], len(rows))

    def test_unknown_visible_and_dns_only_not_usage(self):
        """Unknown sites remain visible; a lookup for a known service is not usage."""
        import_rows(self.store, [observation('new.example', BASE + 3600),
                                 observation('chatgpt.com', BASE + 3601, evidence='DNS query')])
        view = self.store.snapshot(DAY.isoformat())
        self.assertEqual([entry['service'] for entry in view['services']], ['Other websites'])
        self.assertEqual(view['services'][0]['active_seconds'], 0)
        self.assertEqual(len(view['activity']), 2)

    def test_midnight_and_device_separation(self):
        """Service durations clip midnight and keep independent device timelines."""
        rows = [observation('youtube.com', BASE + 86400 - 30),
                observation('youtube.com', BASE + 86400 + 30),
                observation('youtube.com', BASE + 86400 + 60, device='192.168.1.4')]
        import_rows(self.store, rows)
        before = self.store.snapshot('2026-10-14')
        after = self.store.snapshot('2026-10-15')
        self.assertEqual(before['services'][0]['active_seconds'], 30)
        self.assertEqual(len(after['services']), 2)
        self.assertEqual(after['services'][0]['active_seconds'], 30)
        self.assertEqual(after['services'][1]['active_seconds'], 0)
        self.assertEqual(len(self.store.snapshot('2026-10-15', device='192.168.1.4')['services']), 1)

    def test_noise_hours_and_domain_rules(self):
        """Telemetry alone cannot trigger hours/budget alerts unless opted in."""
        for kind, target in (('hours', ''), ('budget', ''), ('domain', 'events.data.microsoft.com'), ('category', 'Unknown')):
            self.store.save_rule(rule(kind, target))
        rows = [observation('browser.events.data.microsoft.com', BASE + 23 * 3600 + offset)
                for offset in (0, 60, 120)]
        import_rows(self.store, rows)
        view = self.store.snapshot(DAY.isoformat())
        self.assertEqual(view['summary']['seconds'], 0)
        self.assertEqual(view['services'], [])
        self.assertEqual({alert['title'] for alert in view['alerts']}, {'domain', 'category'})
        settings = self.store.settings()
        settings['count_background_in_time'] = True
        self.store.save_settings(settings)
        view = self.store.snapshot(DAY.isoformat(), include_background=True)
        self.assertEqual(view['summary']['seconds'], 120)
        self.assertEqual(view['services'][0]['active_seconds'], 120)
        self.assertEqual({alert['title'] for alert in view['alerts']}, {'domain', 'category', 'hours', 'budget'})
        settings['ignored_domains'] = ['events.data.microsoft.com']
        self.store.save_settings(settings)
        view = self.store.snapshot(DAY.isoformat(), include_background=True)
        self.assertEqual(view['summary']['seconds'], 0)
        self.assertEqual({alert['title'] for alert in view['alerts']}, {'domain', 'category'})

    def test_user_exclusions_hidden_but_preserved(self):
        """Parent exclusions are background even without a catalog noise label."""
        import_rows(self.store, [observation('youtube.com', BASE+3600), observation('youtube.com', BASE+3630)])
        settings = self.store.settings()
        settings['ignored_domains'] = ['youtube.com']
        self.store.save_settings(settings)
        self.assertEqual(self.store.snapshot(DAY.isoformat())['services'], [])
        view = self.store.snapshot(DAY.isoformat(), include_background=True)
        self.assertTrue(view['services'][0]['service'].startswith('Background traffic'))
        self.assertEqual(view['activity'][0]['service'], 'YouTube')

    def test_catalog_migration_and_idempotence(self):
        """Old category rows change atomically; a second startup leaves them alone."""
        import_rows(self.store, session_rows())
        self.store.save_rule(rule('category', 'AI'))
        with self.store.connect() as db:
            db.execute("UPDATE events SET category='Unknown'")
            db.execute("UPDATE config SET value='0' WHERE key='catalog_version'")
            db.execute('DELETE FROM alerts')
        migrated = Store(self.path)
        with migrated.connect() as db:
            self.assertEqual(db.execute("SELECT DISTINCT category FROM events WHERE domain='chatgpt.com'").fetchone()[0], 'AI')
            self.assertEqual(db.execute("SELECT value FROM config WHERE key='catalog_version'").fetchone()[0], str(CATALOG_VERSION))
            events = [tuple(row) for row in db.execute('SELECT * FROM events ORDER BY id')]
            self.assertEqual(db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0], 1)
            db.execute('UPDATE alerts SET acknowledged=1')
        with patch.object(Store, 'rebuild_alerts', side_effect=AssertionError('Unnecessary rebuild')):
            again = Store(self.path)
            self.assertFalse(again.refresh_catalog())
        with again.connect() as db:
            self.assertEqual(events, [tuple(row) for row in db.execute('SELECT * FROM events ORDER BY id')])
            self.assertEqual(db.execute('SELECT acknowledged FROM alerts').fetchone()[0], 1)

    def test_catalog_failure_rolls_back(self):
        """Failed alert recategorization cannot leave half-updated event categories."""
        import_rows(self.store, [observation('chatgpt.com', BASE+3600)])
        with self.store.connect() as db:
            db.execute("UPDATE events SET category='Unknown'")
            db.execute("UPDATE config SET value='0' WHERE key='catalog_version'")
        with patch.object(self.store, 'rebuild_alerts', side_effect=RuntimeError('test rollback')):
            with self.assertRaises(RuntimeError):
                self.store.refresh_catalog()
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT category FROM events').fetchone()[0], 'Unknown')
            self.assertEqual(db.execute("SELECT value FROM config WHERE key='catalog_version'").fetchone()[0], '0')
