import csv
import sys
import os
from pathlib import Path
import sqlite3

#pip install pyyaml
import yaml
#pip install -U click
import click
#pip install loguru
from loguru import logger

# convert csv of port names to yaml

class Baseclass:
    def __init__(self,**kwargs):
        # call the super super().__init__(**kwargs)
        for k,v in kwargs.items():
            setattr(self,k,v)

class Config(Baseclass):
    config_filename = "config.yaml"
    config_local_filename = "config_local.yaml"
    data_path = None
    config = None
    def __init__(self,**kwargs):
        super().__init__(**kwargs)
        with open(self.config_filename,'r') as fh:
            self.config = yaml.load(fh,Loader=yaml.FullLoader)
            self.data_path = self.config['data-path']
            if os.path.exists(self.config_local_filename):
                with open(self.config_local_filename,'r') as fh:
                    localconfig = yaml.load(fh,Loader=yaml.FullLoader)
                    if localconfig['data-path']:
                        self.data_path = localconfig['data-path']

class SqlDb(Baseclass):
    filename = None
    config = None
    db_filehandler = None
    delete = None
    _conn = None
    def __init__(self,**kwargs):
        super().__init__(**kwargs)
        self.db_filehandler = FileHandler(config=self.config, 
            filename=self.filename,
            delete=self.delete)
    def _get_connection(self):
        if not self._conn:
            no_db_file = False
            if not os.path.exists( self.db_filehandler.full_path ):
                no_db_file = True
            self._conn = sqlite3.connect( self.db_filehandler.full_path )
            self._conn.row_factory = sqlite3.Row
            #if no_db_file:
            self.create_tables()
        return self._conn
    conn = property(fget=_get_connection)
    def create_tables(self):
        logger.trace(f'Creating table portservice')
        self.cur_execute('''CREATE TABLE IF NOT EXISTS portservice (
            port INTEGER PRIMARY KEY,
            description TEXT DEFAULT '' NOT NULL,
            risk_score INTEGER DEFAULT 0 NOT NULL,
            risk_reason TEXT DEFAULT '' NOT NULL )''')
    def cur_execute(self,sql, params=None):
        
        cur = self.conn.cursor()
        if params:
            return cur.execute(sql,params)
        else:
            return cur.execute(sql)
    def cur_commit(self):
        self.conn.commit()
        

class FileHandler(Baseclass):
    config = None
    filename = None
    data_path = None
    full_path = None
    delete = False
    def __init__(self,**kwargs):
        super().__init__(**kwargs)
        self.data_path = self.config.data_path
        assert self.filename, "No filename set"
        if os.path.exists(self.filename):
            self.full_path = self.filename
            self.data_path = Path(self.filename).parent
            self.filename = Path(self.filename).name
        else:
            self.full_path = os.path.join(self.data_path, self.filename)
        logger.trace(f"full-path {self.full_path}")
        if self.delete:
            self.delete_file()
    def delete_file(self):
        if os.path.exists(self.full_path):
            logger.trace(f'Delete_file {self.full_path}')
            os.remove(self.full_path)

class SourceFile(FileHandler):
    config = None
    filename = None
    data_path = None
    full_path = None
    _is_valid = None
    def __init__(self,**kwargs):
        super().__init__(**kwargs)
        self.is_valid()
    def is_valid(self):
        #Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,
        #Synopsis,Description,Solution,See Also,Plugin Output
        #Asset UUID,Vulnerability State,IP Address,FQDN,NetBios,
        #OS,MAC Address,Plugin Family,CVSS Base Score,CVSS Temporal Score,
        #CVSS Temporal Vector,CVSS Vector,CVSS3 Base Score,CVSS3 Temporal Score,
        #CVSS3 Temporal Vector,CVSS3 Vector,System Type,Host Start,Host End
        if self._is_valid is None:
            with open(self.full_path, 'r', encoding='utf-8') as f:
                headertest = iter(self.config.config['data_file_headers'])
                fileheaders = f.readline().split(self.config.config['delimiter-in'])
                self._is_valid = True
                for header in fileheaders:
                    if header.rstrip() != next(headertest):
                        self._is_valid = False
                        break
        return self._is_valid
                
class PortService(Baseclass):
    data_file = None
    config = None 
    db_filehandler = None
    sqldb = None
    def __init__(self,**kwargs):
        super().__init__(**kwargs)
        self.data_file = self.config.config['port-service-ref']
        self.sqldb = SqlDb(config=self.config,
            filename=self.config.config['port-service-db'],
            delete=False)
    def read_port_datafile(self):
        with open(self.data_file, 'r', encoding='utf-8') as f:  
            reader = csv.DictReader(f)
            n = 0
            for row in reader:
                n += 1
                self.insert_port(row)
                print(row)
                #if n > 10: break
            self.sqldb.cur_commit()
    def insert_port(self, row):
        sql = '''INSERT OR IGNORE INTO portservice (
                port, description, risk_score, 
                risk_reason
                )
            VALUES (
                ?, ?, ?,
                ?
                )'''
        sql_params = (row['port'], row['description'], row['risk_score'],
            row['risk_reason'])
        self.sqldb.cur_execute(sql,sql_params)
    def get_port(self,port):
        sql = '''SELECT description, risk_score, risk_reason
            FROM portservice
            WHERE port = ?'''
        sql_params = (port,)
        data = self.sqldb.cur_execute(sql,sql_params)
        data = data.fetchone()
        return data

@click.group()
@click.option('--debug', is_flag=True)
@click.option('--trace', is_flag=True)
@click.option('--verbose', is_flag=True)
@click.pass_context
def cli(ctx,debug,trace,verbose):
    '''Main entry point for the script'''
    ctx.obj['verbose'] = verbose
    if debug:
        logger.remove(0)
        logger.add(sys.stdout, level='DEBUG')
    if trace:
        logger.remove(0)
        logger.add(sys.stdout, level='TRACE')
    if not debug and not trace:
        logger.remove(0)
        logger.add(sys.stdout, level='INFO')

@cli.command('listports')
@click.option('--i', help='Input filename', default='tenable.csv')
@click.option('--o', help='Output filename', default='ports.csv')
@click.pass_context
def listports(ctx, i, o):
    config = Config()
    sourcefile = SourceFile(config=config, filename=i)
    ps = PortService(config=config)
    if not sourcefile.is_valid():
        print(f"The file {i} is not valid")
    opfile = FileHandler(config=config, filename=o, delete=True)

    with open(sourcefile.full_path, 'r', encoding='utf-8') as f: 
        hosts = {}
        reader = csv.DictReader(f)
        for row in reader:
            if row['Host'] not in hosts.keys():
                hosts[row['Host']] = {}
                hosts[row['Host']]['IP Address'] = row['IP Address']
                hosts[row['Host']]['ports'] = []
            if row['Port'] != '0' and int(row['Port']) not in hosts[row['Host']]['ports']: 
                hosts[row['Host']]['ports'].append(int(row['Port']))
                hosts[row['Host']]['ports'].sort()
    
    with open(opfile.full_path,'w',encoding='utf-8',newline='\n') as f:
        headers = []
        for header in config.config['output_port_file_headers']:
            headers.append(header.replace('calculated_',''))
        writer = csv.DictWriter(f,delimiter=config.config['delimiter-out'],
                    fieldnames= headers )
        writer.writeheader()
        for k,v in hosts.items():
            outrow = {}
            outrow['Host'] = k
            outrow['IP Address'] = v['IP Address']
            for port in v['ports']:
                outrow['Port'] = port
                portdetail = ps.get_port(port)
                if portdetail:
                    outrow['Service'] = portdetail['description']
                else:
                    outrow['Service'] = ''
                writer.writerow(outrow)
                print(f"{k} {port}")

@cli.command('listvulns')
@click.option('--i', help='Input filename',default='tenable.csv')
@click.option('--o', help='Output filename',default='vulns.csv')
@click.pass_context
def listvulns(ctx, i, o):
    config = Config()
    sourcefile = SourceFile(config=config, filename=i)
    if not sourcefile.is_valid():
        print(f"The file {i} is not valid")
    opfile = FileHandler(config=config, filename=o, delete=True)

    with open(sourcefile.full_path, 'r', encoding='utf-8') as f: 
        hosts = {}
        reader = csv.DictReader(f)
        for row in reader:
            if row['Host'] not in hosts.keys():
                hosts[row['Host']] = {}
                hosts[row['Host']]['IP Address'] = row['IP Address']
                hosts[row['Host']]['names'] = []
            if row['Risk'] in config.config.get('vuln-ignore',None):
                continue
            if (row['Risk'],row['Name']) not in hosts[row['Host']]['names']: 
                hosts[row['Host']]['names'].append( (row['Risk'], row['Name']) )
                hosts[row['Host']]['names'].sort()
    
    with open(opfile.full_path,'w',encoding='utf-8',newline='\n') as f:
        headers = []
        for header in config.config['output_vuln_file_headers']:
            headers.append(header.replace('calculated_',''))
        writer = csv.DictWriter(f,delimiter=config.config['delimiter-out'],
                    fieldnames= headers )
        writer.writeheader()
        for k,v in hosts.items():
            outrow = {}
            outrow['Host'] = k
            outrow['IP Address'] = v['IP Address']
            for name in v['names']:
                outrow['Name'] = name
                outrow['Risk'] = name[0]
                outrow['Name'] = name[1]
                writer.writerow(outrow)
                print(f"{k} {name}")
    
@cli.command('portservice')
@click.pass_context
def portservice(ctx):
    config = Config()
    ps = PortService(config=config)
    ps.read_port_datafile()
    

if __name__ == '__main__':
    cli(obj={})