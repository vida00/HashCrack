#!/usr/bin/python

#####################################################################
# + Observacoes:
# Titulo: hashcrack
# Versao: 1.0
# Autor: vida
# Funcao: Quebrar hashs comuns e quebrar hashs com salt
# Testado no: Kubunto
# + Fim
#####################################################################

#############################################
# Bibliotecas
#############################################
import sys, crypt, hashlib, os
from pathlib import Path

#############################################
# Variaveis para facilitar o uso das cores
#############################################
magenta="\033[35;01;1m"
vermelho="\033[31;01;1m"
amarelo="\033[33;01;1m"
cinza="\033[30;01;1m"
end="\033[m"

#############################################
# Banner
#############################################
def __banner__():
	print magenta+"""
  _            _    ___             _
 | |_  __ _ __| |_ / __|_ _ __ _ __| |__
 | ' \/ _` (_-< ' \ (__| '_/ _` / _| / /
 |_||_\__,_/__/_||_\___|_| \__,_\__|_\_\ v1

 Coded by vida :)
 hashcrack.py -h
	"""+end

#############################################
# Menu Help
#############################################
def __help__():
	print cinza+"Usage: hashcrack.py [OPTION] [HASH] [WORDLIST]\n"+end
	print cinza+"Opcao:\t\t\tFuncao:"+end
	print cinza+"-md5\t\t\tDefine Hash Sem Salt do tipo MD5"+end
	print cinza+"-sha1\t\t\tDefine Hash Sem Salt do tipo SHA1"+end
	print cinza+"-sha256\t\t\tDefine Hash Sem Salt do tipo SHA-256"+end
	print cinza+"-sha512\t\t\tDefine Hash Sem Salt do tipo SHA-512"+end
	print cinza+"-salt\t\t\tQuebra de hash com salt"+end
	print cinza+"-w, --wordlist\t\tDefine a wordlist a ser usada"+end
	print cinza+"-h, --help\t\tAbre o help"+end
	print cinza+"-f, --formats\t\tMostra os formatos suportados"+end
	print cinza+"-v, --version\t\tMostra a versao atual do hashcrack"+end

#############################################
# Variavel armazenando a versao do hashcrack
#############################################
ver = '1.0'

#############################################
# Funcao para pegar os formatos suportados
#############################################
def __formatos__():
	print cinza+"Formatos Suportas:"+end+vermelho+"\n-> md5, sha1, sha256, sha512"+end

#############################################
# Funcao para pegar o tamanho da wordlist
#############################################
def convert_bytes(num):
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0
def file_size(file_path):
        file_info = os.stat(file_path)
        return convert_bytes(file_info.st_size)

#############################################
# Funcao HashCrack Sem Salt
#############################################
def __hsSS__():
	tipo_hash = sys.argv[1]
	if Path(sys.argv[4]).is_file():
		wdSS = open(sys.argv[4], 'r')
		linhas = len(open(sys.argv[4]).readlines())
		print cinza+"============================================================"+end
		print cinza+"Wordlist: "+end+vermelho+sys.argv[4]+end
		print cinza+"Tamanho: "+end+vermelho+file_size(sys.argv[4])+end
		print cinza+"Linhas: "+end+vermelho+"{}".format(linhas)+end
		print cinza+"============================================================"+end
	else:
		print vermelho+"Arquivo Inexistente"+end
		sys.exit(1)
	hashSS = sys.argv[2]
	for line in wdSS:
		line = line.strip("\n")
		if tipo_hash == "-md5":
			line_hsSS = hashlib.md5(line).hexdigest()
		elif tipo_hash == "-sha1":
			line_hsSS = hashlib.sha1(line).hexdigest()
		elif tipo_hash == "-sha256":
			line_hsSS = hashlib.sha256(line).hexdigest()
		elif tipo_hash == "-sha512":
			line_hsSS = hashlib.sha512(line).hexdigest()
		else:
			print vermelho+"Tipo Invalido"+end
		if line_hsSS == hashSS:
			print amarelo+"[+] Senha Encontrada: "+line,end
			sys.exit(0)
			break
			wdSS.close()
		else:
			print cinza+"[-] Tentando: "+end,line
			continue
	print vermelho+"Nada Encontrado :("+end
	wdSS.close()

#############################################
# Funcao HashCrack Com Salt
#############################################
def __hsCS__():
	if Path(sys.argv[3]).is_file():
		wdCS = open(sys.argv[3], 'r')
		linhas = len(open(sys.argv[3]).readlines())
		print cinza+"============================================================"+end
		print cinza+"Wordlist: "+end+vermelho+sys.argv[3]+end
		print cinza+"Tamanho: "+end+vermelho+file_size(sys.argv[3])+end
		print cinza+"Linhas: "+end+vermelho+"{}".format(linhas)+end
		print cinza+"============================================================"+end
	else:
		print vermelho+"Arquivo Inexistente"+end
		sys.exit(1)
	hashCS = raw_input(cinza+"Hash Completa (SALT+HASH): "+end)
	f = hashCS.split('$')
	try:
		dic = {	'tipo'	:	f[1],	\
			'salt'	:	f[2],	\
			'hash'	:	f[3]
			}
	except:
		print vermelho+"Formato Invalido"+end
		sys.exit(1)
	salt_completo = "$"+dic['tipo']+"$"+dic['salt']+"$"
	if dic['tipo'] == "1":
		print cinza+"[+] "+end+vermelho+"MD5 Decrypt"+end+cinza+" [+]"+end
		print cinza+"============================================================\n"+end
	elif dic['tipo'] == "2a":
		print cinza+"[+] "+end+vermelho+"BlowFish Decrypt"+end+cinza+" [+]"+end
		print cinza+"============================================================\n"+end
	elif dic['tipo'] == "5":
		print cinza+"[+] "+end+vermelho+"SHA-256 Decrypt"+end+cinza+" [+]"+end
		print cinza+"============================================================\n"+end
	elif dic['tipo'] == "6":
		print cinza+"[+] "+end+vermelho+"SHA-512 Decrypt"+end+cinza+" [+]"+end
		print cinza+"============================================================\n"+end
	else:
		print "\n---------------------------------------------"
		print cinza+"[-] No Hash Type Identified [-]"+end
		print "---------------------------------------------\n"

	for line in wdCS:
		line = line.strip("\n")
		line_hs = crypt.crypt(line,salt_completo)
		if line_hs == hashCS:
			print amarelo+"[+] Senha Encontrada: "+line,end
			sys.exit(0)
			break
			wdSS.close()
		else:
			print cinza+"[-] Tentando: "+end,line
			continue
	print vermelho+"Nada Encontrado :("+end
	wdCS.close()


#############################################
# Funcao Main
#############################################
def __Main__():
	if len(sys.argv) > 5 or len(sys.argv) == 1:
		__banner__()
		sys.exit(1)
	elif sys.argv[1] == "-h" or sys.argv[1] == "--help":
		__help__()
		sys.exit(0)
	elif sys.argv[1] == "-f" or sys.argv[1] == "--formats":
		__formatos__()
		sys.exit(0)
	elif sys.argv[1] == "-v" or sys.argv[1] == "--version":
		print cinza+"Versao: "+ver,end
		sys.exit(0)
	elif len(sys.argv) == 4:
		if sys.argv[1] == "-salt" and sys.argv[2] == "-w" or sys.argv[2] == "--wordlist":
			__hsCS__()
			sys.exit(0)
		else:
			__help__()
			sys.exit(1)
	elif len(sys.argv) == 5:
		if sys.argv[1] == "-md5" and sys.argv[3] == "-w" or sys.argv[3] == "--wordlist" or sys.argv[1] == "-sha1" and sys.argv[3] == "-w" or sys.argv[3] == "--wordlist" or sys.argv[1] == "-sha256" and sys.argv[3] == "-w" or sys.argv[3] == "--wordlist" or sys.argv[1] == "-sha512" and sys.argv[3] == "-w" or sys.argv[3] == "--wordlist":
			__hsSS__()
			sys.exit(0)
		else:
			__help__()
			sys.exit(1)
	else:
		__help__()
		sys.exit(1)
#############################################
# Iniciando o Software
#############################################
try:
	__Main__()
except KeyboardInterrupt:
	print vermelho+"\nAcao Abortada"+end
	sys.exit(1)
