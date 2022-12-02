import glob
from pathlib import Path
import os
import json

if __name__ == '__main__':
  for file_in in glob.glob('json/*.json', recursive=True):
    with open(file_in, 'r', encoding='utf-8') as fr:
      cont = json.load(fr)
      with open(file_in, 'w', encoding='utf-8') as fw:
        write_data = (f'{json.dumps(cont, indent=2, ensure_ascii=False)}')
        fw.write(write_data)
