import csv
import sys
import os
from pathlib import Path

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
    def delete_file():
        if os.path.exists(filename):
            logger.trace(f'Delete_file {filename}')
            os.remove(filename)

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
                writer.writerow(outrow)
                print(f"{k} {port}")

@cli.command('listvulns')
@click.option('--i', help='Input filename',default='tenable.csv')
@click.option('--o', help='Output filename',default='vulns.csv')
@click.pass_context
def listports(ctx, i, o):
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
    

    

if __name__ == '__main__':
    cli(obj={})