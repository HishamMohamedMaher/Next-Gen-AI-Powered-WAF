import tempfile
import unittest
import zipfile
from pathlib import Path
import pandas as pd
from training.clean_data import load_srbh, load_httpparams

class Day1LoaderTests(unittest.TestCase):
    def test_srbh_binary_multilabel(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'mini.csv'
            pd.DataFrame([
                {'request_http_method':'GET','request_http_request':'/home','request_body':'',
                 '000 - Normal':'1','66 - SQL Injection':'0','126 - Path Traversal':'0'},
                {'request_http_method':'POST','request_http_request':'/?q=UNION%20SELECT','request_body':'x=1',
                 '000 - Normal':'0','66 - SQL Injection':'1','126 - Path Traversal':'1'},
            ]).to_csv(p, index=False)
            out = load_srbh(p)
            self.assertEqual(list(out.columns), ['payload','label','attack_type'])
            self.assertEqual(out['label'].tolist(), [0,1])
            self.assertIn('66 - SQL Injection', out['attack_type'][1])
            self.assertEqual(out['payload'][1], 'POST /?q=UNION%20SELECT\nx=1')
    def test_srbh_conflicting_label_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'bad.csv'
            pd.DataFrame([{'request_http_method':'GET','request_http_request':'/',
                'request_body':'','000 - Normal':'1','66 - SQL Injection':'1'}]).to_csv(p,index=False)
            with self.assertRaises(ValueError): load_srbh(p)
    def test_httpparams_zip_train_only(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'h.zip'
            with zipfile.ZipFile(p,'w') as z:
                z.writestr('x/payload_train.csv','payload,label,attack_type\nhello,norm,none\nunion,anom,sqli\n')
                z.writestr('x/payload_test.csv','payload,label,attack_type\nNEVER_READ,anom,xss\n')
            out = load_httpparams(p)
            self.assertEqual(out['label'].tolist(), [0,1])
            self.assertEqual(len(out), 2)
            self.assertNotIn('NEVER_READ', out['payload'].tolist())
    def test_unknown_httpparams_label_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'bad.csv'
            pd.DataFrame({'payload':['x'],'label':['???']}).to_csv(p,index=False)
            with self.assertRaises(ValueError): load_httpparams(p)

if __name__ == '__main__': unittest.main()
