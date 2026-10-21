import tempfile
import unittest
from pathlib import Path
import pandas as pd
from training.clean_data import (deduplicate, remove_headers, load_baseline,
                                 scan_mislabeled, normalize_all, clean_pipeline)
from training.prepare_features import split_data, save_splits, load_cleaned_data


class Member3Week1Tests(unittest.TestCase):
    def test_dedup_sha256_and_conflicts(self):
        df = pd.DataFrame({'payload':['GET /ok','GET /ok','POST /x'], 'label':[0,0,1],
                           'attack_type':['benign','benign','sqli']})
        out = deduplicate(df)
        self.assertEqual(len(out),2)
        self.assertEqual(out.request_group_sha256.str.len().tolist(),[64,64])
        with self.assertRaisesRegex(ValueError,'Conflicting'):
            deduplicate(pd.DataFrame({'payload':['same','same'],'label':[0,1]}))

    def test_remove_headers_without_destroying_body(self):
        raw = 'POST /login?q=1 HTTP/1.1\r\nHost: example.com\r\nCookie: secret\r\n\r\na=1&b=2'
        self.assertEqual(remove_headers(raw),'/login?q=1\na=1&b=2')
        self.assertEqual(remove_headers('GET /ok'),'/ok')
        self.assertEqual(remove_headers('POST /submit\nx=1'),'/submit\nx=1')
        self.assertEqual(remove_headers('hello=world'), 'hello=world')

    def test_baseline_explicit_benign_only(self):
        with tempfile.TemporaryDirectory() as d:
            good=Path(d)/'good.csv'
            pd.DataFrame({'method':['GET','POST'],'path':['/','/login'],
                          'body':['','a=b'],'label':[0,0]}).to_csv(good,index=False)
            result=load_baseline(good)
            self.assertEqual(result.label.tolist(),[0,0])
            self.assertEqual(result.payload.iloc[1],'POST /login\na=b')
            bad=Path(d)/'bad.csv'
            pd.DataFrame({'payload':['/admin'],'label':[1]}).to_csv(bad,index=False)
            with self.assertRaises(ValueError): load_baseline(bad)

    def test_three_way_group_isolation_and_splits(self):
        df=pd.DataFrame([{'payload':f'{cl}{i}', 'label':cl, 'attack_type':'x',
                           'request_group_sha256':f'{cl}{i:063x}'[-64:]}
                         for cl in [0,1] for i in range(30)])
        train,val,test=split_data(df, random_state=42)
        self.assertEqual(len(train)+len(val)+len(test),len(df))
        keys=[set(p.request_group_sha256) for p in (train,val,test)]
        self.assertFalse(keys[0]&keys[1] or keys[0]&keys[2] or keys[1]&keys[2])
        self.assertAlmostEqual(len(train)/len(df), .7, delta=.05)
        with tempfile.TemporaryDirectory() as d:
            location=Path(d)/'output'
            save_splits(train,val,test,location)
            self.assertTrue((location/'split_manifest.json').is_file())
            self.assertEqual(len(load_cleaned_data(location/'srbh_train_raw.csv')), len(train))
            with self.assertRaises(FileExistsError):
                save_splits(train,val,test,location)

    def test_fail_closed_when_normalizer_is_unavailable(self):
        from unittest.mock import patch
        df=pd.DataFrame({'payload':['GET /'], 'label':[0]})
        with patch('training.clean_data.normalize_text', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'WAITING_ON_MEMBER_2'):
                normalize_all(df)
        # A production-ready pipeline cannot be declared before serving parity.
        with self.assertRaisesRegex(RuntimeError, 'BLOCKED_FOR_REAL_TRAINING'):
            clean_pipeline('/does/not/matter','/not-created')
        self.assertTrue(callable(scan_mislabeled))
