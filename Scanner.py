import os
import time
import getpass
import logging
import requests
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from hashlib import md5

# Configuração do logger
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()

# Adicionando um manipulador de arquivo para registrar as mensagens de log em um arquivo de relatório
file_handler = logging.FileHandler('relatorio.log')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logger.addHandler(file_handler)

# Funções para cálculo de hash MD5 e verificação de arquivo com VirusTotal
def calculate_md5(file_path):
    """
    Calcula o hash MD5 de um arquivo.
    """
    md5_hash = md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def scan_file(file_path, api_key):
    """
    Verifica se um arquivo é malicioso utilizando a API do VirusTotal.
    Retorna o resultado do scan em formato JSON.
    """
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
    response = requests.post(url, files=files, params=params)
    return response.json()

def get_report(resource, api_key):
    """
    Obtém o relatório de um arquivo específico da API do VirusTotal.
    Retorna o resultado do scan em formato JSON.
    """
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': resource}
    response = requests.get(url, params=params)
    return response.json()

def send_to_wazuh(message, wazuh_url, wazuh_token):
    """
    Envia uma mensagem para o Wazuh.
    """
    headers = {
        'Authorization': f'Bearer {wazuh_token}',
        'Content-Type': 'application/json'
    }
    
    data = {
        'data': message,
        'log': 'my_watchdog_logs'
    }
    
    try:
        response = requests.post(f"{wazuh_url}/logs", headers=headers, json=data)
        if response.status_code == 201:
            logger.info("Log enviado para o Wazuh com sucesso.")
        else:
            logger.error(f"Falha ao enviar log para o Wazuh: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"Erro ao enviar log para o Wazuh: {e}")

class MyHandler(FileSystemEventHandler):
    def __init__(self, api_key, wazuh_url, wazuh_token):
        super().__init__()
        self.api_key = api_key
        self.wazuh_url = wazuh_url
        self.wazuh_token = wazuh_token
        # Dicionário para rastrear o último tempo de modificação de cada arquivo
        self.last_modified = {}

    def on_created(self, event):
        if not event.is_directory:
            message = f"Novo arquivo criado por {getpass.getuser()}: {event.src_path}"
            logger.info(message)
            send_to_wazuh(message, self.wazuh_url, self.wazuh_token)
            
            file_path = event.src_path
            md5_hash = calculate_md5(file_path)
            logger.info(f"Verificando o arquivo '{os.path.basename(file_path)}' no VirusTotal...")
            scan_result = scan_file(file_path, self.api_key)
            scan_id = scan_result['scan_id']
            while True:
                report = get_report(md5_hash, self.api_key)
                if report['response_code'] == 1:
                    positives = report['positives']  # Número de antivírus que detectaram o arquivo
                    total = report['total']  # Total de antivírus que escanearam o arquivo
                    
                    # Exibe a mensagem formatada
                    logger.info(f"O VirusTotal detectou {positives}/{total} antivírus.")
                    
                    # Geração do link para o relatório completo no VirusTotal
                    vt_report_url = f"https://www.virustotal.com/gui/file/{md5_hash}/detection"
                    logger.info(f"Aqui está o link do scan: {vt_report_url}")
                    break

    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            current_time = time.time()
            
            # Verifica se já passou tempo suficiente desde a última modificação para evitar logs repetidos
            if file_path in self.last_modified:
                # Se o arquivo foi modificado há menos de 2 segundos, não registrar novamente
                if current_time - self.last_modified[file_path] < 2:
                    return

            # Atualiza o tempo da última modificação
            self.last_modified[file_path] = current_time

            # Exibe o aviso no log para modificações
            message = f"Atenção! O arquivo '{os.path.basename(file_path)}' foi modificado por {getpass.getuser()}."
            logger.info(message)
            send_to_wazuh(message, self.wazuh_url, self.wazuh_token)

    def on_deleted(self, event):
        if not event.is_directory:
            message = f"Arquivo excluído por {getpass.getuser()}: {event.src_path}"
            logger.info(message)
            send_to_wazuh(message, self.wazuh_url, self.wazuh_token)

# Inicializar o observador
diretorio_origem = "C:\\Users\\gusta\\Desktop\\test"  # Substitua pelo seu diretório de monitoramento
api_key = "apikey"  # Substitua pela sua API key do VirusTotal
wazuh_url = "http://192.168.100.5:55000"  # Substitua pelo endereço do servidor Wazuh
wazuh_token = "tokem"  # Substitua pelo seu token de autenticação

observer = Observer()
observer.schedule(MyHandler(api_key, wazuh_url, wazuh_token), path=diretorio_origem, recursive=True)
observer.start()

try:
    while True:
        time.sleep(60)
except KeyboardInterrupt:
    observer.stop()

observer.join()
