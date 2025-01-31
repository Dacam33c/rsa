
from random import randint
import random as rand
import os
import base64
import hashlib
import traceback
from typing import *


def MillerRabin(n, iteracoes):
    #n = numero testado
    #iteracoes aumenta a confiabilidade do teste
    
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(iteracoes):
        a = rand.randint(2, n - 2)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def GeradorPrimos():
    teste = 0
    while(True):
        n = randint(2**1023,(2**1024)-1)
        teste +=1
        if(MillerRabin(n,10)):
            return n

#N1 deve ser maior que N2
def euclides(n1,n2):
    while(n2 != 0):
        n1, n2 = n2, n1 % n2
    return n1 == 1
    
def makeKey(primo1,primo2):
    if (primo1 == primo2):
        print("primos aleatórios iguais")
        return 0
    
    n = primo1 * primo2
    phi = (primo1 - 1) * (primo2 - 1)
    e = randint(1,phi)
    #CHAMAR FUNÇÃO DE EUCLIDES COM N1>N2!!!!!!!!!
    while (not euclides(phi,e)):
        e = randint(1,phi)
        
    #d é o inverso multiplicativo mod phi de e
    #significa que, ao multiplicar d * e e entao tirar mod phi o resultado será 1
    
    d = pow(e, -1, phi)
    #print("phi:", phi)
    #print("chave pública e:",e)
    #print("chave privada d:",d)
    return e,n,d


# publicKey(e),publicExp(n),privateKey(d) = makeKey(GeradorPrimos(),GeradorPrimos())

#função de encriptação. recebe um texto com hash OAEP, chave privada "d" e expoente publico "n"
def encriptar(mensagem, d, n):
    #transforma a mensagem codificada em um tipo que podemos operar
    msg = int.from_bytes(mensagem, 'big')
    #msg elevado a "e" no modulo "n"
    msgEncriptada = pow(msg,d,n)
    #retorna a mensagem com rsa e OAEP aplicados
    return(msgEncriptada)

#função de decriptaçao. recebe texto encriputado e com OAEP, chave publica "e" e expoente publico "n"
def decriptar(textoEncriptado, e, n):
    #texto elevado a "d" no modulo "n"
    msg = pow(textoEncriptado, e, n)
    #tamanho da mensagem
    tamanho = (n.bit_length() + 7) // 8
    #converte para bytes
    msgDecriptadaOAEP = msg.to_bytes(tamanho, 'big')
    #retorna a mensagem, com rsa decriptado mas ainda com OAEP
    return msgDecriptadaOAEP
    

def mask(seed, length, hash_func=hashlib.sha3_256):
    counter = 0
    output = b''
    while len(output) < length:
        counter_bytes = counter.to_bytes(4, 'big')
        output += hash_func(seed + counter_bytes).digest()
        counter += 1
    return output[:length]

def encode(message, k, hash_func=hashlib.sha3_256):
    hashLen = hash_func().digest_size  # 32 bytes
    messageLen = len(message)
    label = b''

    if messageLen > k - 2 * hashLen - 2:
        raise ValueError("mensagem muito longa")
        return 1
    
    #gera string aleatoria
    seed = os.urandom(hashLen)
    #aplica função de rash e armazena o valor em bytes
    labelHash = hash_func(label).digest()

    #cria um bloco de dados do tamanho certo com label na frente
    ps = b'\x00' * (k - messageLen - 2 * hashLen - 2)
    db = labelHash + ps + b'\x01' + message.encode(encoding="utf-8")

    #aplica mascara ao data block
    dbMask = mask(seed, len(db), hash_func)
    maskeddb = bytes(a ^ b for a, b in zip(db, dbMask))

    #aplica mascara a seed
    seedMask = mask(maskeddb, hashLen, hash_func)
    maskedSeed = bytes(a^b for a,b in zip(seed,seedMask))

    return b'\x00' + maskedSeed + maskeddb

def decode(message,k, hash_func=hashlib.sha3_256):
    label = b''
    hashLen = hash_func().digest_size
    if len(message) != k:
        raise ValueError("tamanho incorreto")

    #separando componentes
    _, maskedSeed, maskeddb = message[0], message[1:hashLen+1], message[hashLen+1:]

    #recuperando seed
    seedMask = mask(maskeddb, hashLen, hash_func)
    seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))

    #recuperando data block
    dbMask = mask(seed, len(maskeddb), hash_func)
    db = bytes(a ^ b for a, b in zip(maskeddb, dbMask))

    #extraindo mensagem
    tamanhoHash = hash_func(label).digest()

    print(f"\ntamanhoHash = {tamanhoHash}")
    print(f"len(tamanhoHash) = {len(tamanhoHash)}")
    print(f"\ndb[:hashLen] = {db[:hashLen]}")
    print(f"type(db[:hashLen]) = {len(db[:hashLen])}")
    print(f'\n\niguais? {db[:hashLen] == tamanhoHash}')
    

    if db[:hashLen] != tamanhoHash:
        raise ValueError("label hash incorreto")

    #encontrando \x01 e extraindo mensagem
    index = db.find(b'\x01', hashLen)
    if index == -1:
        raise ValueError("formato invalido")
    
    return db[index+1:]


def assinar_arquivo( file_name_ext:str, prk_file:str ) -> None:

    ''' 
        função pra assinar um arquivo, gerando um arquivo em base 64 da mensagem (bytes do arquivo),
        hash da mensagem e os outras informações para verificação.
        o arquivo resultante terá a extensão '.b64' e possuirá a seguinte estrutrura:
            - primeiros 2 bytes -> quantidade 'n' de caracteres do hash criptografado
            - proximos n bytes -> hash criptografado do arquivo da mensagem
            - byte seguinte -> numero 'c' de caracteres de extensão do arquivo da mensagem
            - próximos c bytes - extensão do arquivo da mensagem
            - resto dos bytes - arquivo da mensagem
    '''

    # tenta ler arquivo da mensagem como bytes e arquivo da chave privada, retorna None em caso de erro
    try:
        with open(f'./.files/{file_name_ext}', 'rb') as f:
            file_bytes = f.read()
        with open(f'./.prk/{prk_file}', 'r') as f:
            prk = f.readlines()
    except Exception as exc:
        print(f'\nERRO!!!: {exc}')
        print(f"TRACEBACK:\n{traceback.format_exc()}")
        return None

    d = int(prk[0], 16)
    n = int(prk[1], 16)

    # caso não dê erro na leitura dos bytes do arquivo:
    # calcula hash sha3_256 dos bytes do arquivo como um string
    hash_str = hashlib.sha3_256(file_bytes).hexdigest()
    
    print(f'\nhash_str = {hash_str}')

    # codificação OAEP e encriptação (assinatura com a chave privada)
    hash_bytes_encod = encode(hash_str, (d.bit_length() + 7) // 8)
    hash_bytes_cript = str(encriptar(hash_bytes_encod, d, n)).encode("utf-8")

    print(f'\nhash_bytes_cript = {hash_bytes_cript}')

    # obtem representação em bytes do tamnho do hash encriptado
    len_hash_bytes_cript = len(hash_bytes_cript).to_bytes(2, "big")

    print(f'\nlen_hash_bytes_cript = {len_hash_bytes_cript}')

    # concatena comprimento do hash e o hash
    msg_1 = len_hash_bytes_cript + hash_bytes_cript

    # obtém nome e extensão do arquivo
    file_name, file_extension = os.path.splitext(file_name_ext)
    num_char_file_ext = len(file_extension) - 1 # ignora o '.'

    # constroi dados enviados junto ao comrimento do hash e o proprio hash
    msg_2 = num_char_file_ext.to_bytes(1, "big") + file_extension[1:].encode(encoding = "utf-8") + file_bytes

    # mensagem final
    msg_final = msg_1 + msg_2

    # converte para base 64
    msg_final_b64 = base64.b64encode(msg_final)

    # tenta salvar
    try:
        with open(f"./.b64/{file_name}_{prk_file[:-4]}_signed.b64", "wb") as f:
            f.write(msg_final_b64)
        print(f"\narquivo assinado e convertido para base 64 gerado e salvo em '.b64/{file_name}_{prk_file[:-4]}_signed.b64'\n")
    except Exception as exc:
        print(f"\nERRO!!!: {exc}")
        print(f"NÃO FOI POSSÍVEL SALVAR ARQUIVO '.b64/{file_name}_signed.b64'")
        print(f"TRACEBACK:\n{traceback.format_exc()}")


'''
    função para verificar a assinatura, decodificando o arquivo b64 gerado na função anterior, a partir
    dos mesmos critérios.
    reconstrói o arquivo da mensagem original
'''
def verificar_assinatura( b64_file_name:str, puk_file:str ) -> None:

    # tenta ler arquivo b64 como string e arquivo da chave publica, retorna None em caso de erro
    try:
        with open(f"./.b64/{b64_file_name}", "r") as f:
            b64_file = f.read()
        with open(f"./.puk/{puk_file}") as f:
            puk = f.readlines()
    except Exception as exc:
        print(f"\nERRO!!!: {exc}")
        print(f"NÃO FOI POSSÍVEL LER ARQUIVOS './.b64/{b64_file_name}' e './.puk/{puk_file}'")
        print(f"TRACEBACK:\n{traceback.format_exc()}")
        return
    
    e = int(puk[0], 16)
    n = int(puk[1], 16)

    print(f'\ne = {e}')
    print(f'\nn = {n}')

    # decodifica arquivo base 64 'recebido'
    msg_bytes = base64.b64decode(b64_file)

    # extrai o tamanho do hash criptografado
    len_hash_crip = int.from_bytes(msg_bytes[:2], "big")

    # extrai hash criptografado
    hash_received_encrp = msg_bytes[2:2+len_hash_crip]
    print(f'\nhash_received_encrp = {hash_received_encrp}')

    # decriptografa com a chave pública (e,n)
    hash_received_decrp = decriptar(int(hash_received_encrp), e, n)
    print(f'\nhash_received_decrp = {hash_received_decrp}')

    # decodifica OAEP (e depois utf-8)
    hash_received = decode(hash_received_decrp, (e.bit_length() + 7) // 8).decode("utf-8")

    # extrai numero de caracteres da extensão do arquivo
    num_char_file_ext = int.from_bytes(msg_bytes[2+len_hash_crip:1+2+len_hash_crip],"big")

    # extrai extensão do arquico
    file_extension = msg_bytes[1+2+len_hash_crip:1+2+len_hash_crip+num_char_file_ext].decode(encoding="utf-8")

    # extrai bytes do arquivo enviado
    file_received_bytes = msg_bytes[1+2+len_hash_crip+num_char_file_ext:]

    # nome do arquivo original (ignora o '_signed.b64')
    file_name = b64_file_name[:-11]

    # calcula hash da mensagem recebida
    hash_calculated = hashlib.sha3_256(file_received_bytes).hexdigest()

    # flag
    validated = True

    print(f'\nhash_calculated = {hash_calculated}')
    print(f'\nhash_received = {hash_received}')

    # compara os hashes (verifica assinatura)
    if hash_calculated == hash_received:
        print("\nassinatura válida !!! aeee :) ")
    else:
        print("\nassinatura invalidada !!!  :( ")
        validated = False

    print('\nRestaurando arquivo...')

    try:
        with open(f"./.checked_files/{file_name}_{puk_file[:-4]}_{'validated' if validated else 'invalidated'}.{file_extension}", "wb") as f:
            f.write(file_received_bytes)
    except Exception as exc:
            print(f"\nERRO!!!: {exc}")
            print("NÃO FOI POSSÍVEL RESTAURAR ARQUIVO VERIFICADO")
            print(f"TRACEBACK:\n{traceback.format_exc()}")
            return
    
    print(f"./.checked_files/{file_name}_{puk_file[:-4]}_{'validated' if validated else 'invalidated'}.{file_extension}")


'''
    função para printar as opções do programa para o usuário, e reagir de acordo
'''
def opcoes_iniciais() -> Optional[int] :
    print("\nEscolha uma opção:")
    print("1 - Gerar chaves")
    print("2 - Assinar arquivo")
    print("3 - Verificar assinatura")
    print("\nDigite 's' para sair.")
    op = input("\n> ")
    if not op.isalnum() or not op in ("1","2","3","s","S"):
        print("\nOpção inválida\n\n")
    return op

def salvar_chaves() -> None:
    '''
        função para salvar a chave publica na pasta .pub e a chave privada na pasta .prv
        a primeira linha do arquivo é a expoente. a segunda linha é o n
    '''
    while True:
        print("\nEscolha um nome para o arquivos das chaves pública e privada.")
        print("Obs: O nome deve conter apenas caracteres alfanuméricos e ter no mínimo 2 e no máximo 255 caracteres.\n")
        print("Digite 'v' para voltar.\n")
        entrada = input('> ')

        if entrada.lower() == 'v': return
        if not entrada.isalnum() or not 2<len(entrada)<256:
            print("\nO nome deve conter apenas caracteres alfanuméricos e ter no mínimo 2 e no máximo 255 caracteres.")
        else:
            name = entrada
            print("\nGerando chaves...")
            puk, n, prk = makeKey(GeradorPrimos(), GeradorPrimos())
            try:
                with open(f"./.puk/{name}.puk", "w") as f:
                    f.writelines([hex(puk)[2:], "\n", hex(n)[2:]])
                    print(f"A chave publica foi salva em './.puk/{name}.puk'")
                with open(f"./.prk/{name}.prk", "w") as f:
                    f.writelines([hex(prk)[2:], "\n", hex(n)[2:]])
                    print(f"A chave privada foi salva em './.prk/{name}.prk'")        
                return
            except Exception as exc:
                print(f"\nERRO!!!: {exc}")
                print("NÃO FOI POSSÍVEL SALVAR CHAVES")
                print(f"TRACEBACK:\n{traceback.format_exc()}")
                return



'''
    função para mostrar as opções de chaves privadas disponíveis para assinatura na pasta ./.prk, e
    retornar o nome do arquivo da chave privada escolhida para a função principal
'''
def opcoes_chaves_privadas() -> Optional[str] :
    while True:
        prks = os.listdir("./.prk")
        print("\nEscolha umas das chaves privadas em ./.prk:")
        for idx_prk in range(len(prks)):
            print(f"{idx_prk+1} - {prks[idx_prk]}")
        print("\nDigite 'v' para voltar")
        op = input("\n> ")
        if op.lower() == 'v': return
        if not op.isalnum or op not in [str(x) for x in list(range(1,len(prks)+1))]:
            print("\nOpção inválida")
        else:
            prk_file = prks[int(op)-1]
            return prk_file


'''
    função para mostrar as opções de chaves publicas disponíveis para assinatura na pasta ./.puk, e
    retornar o nome do arquivo da chave publica escolhida para a função principal
'''
def opcoes_chaves_publicas() -> Optional[str] :
    while True:
        puks = os.listdir("./.puk")
        print("\nEscolha umas das chaves publicas em ./.puk:")
        for idx_puk in range(len(puks)):
            print(f"{idx_puk+1} - {puks[idx_puk]}")
        print("\nDigite 'v' para voltar")
        op = input("\n> ")
        if op.lower() == 'v': return
        if not op.isalnum or op not in [str(x) for x in list(range(1,len(puks)+1))]:
            print("\nOpção inválida")
        else:
            puk_file = puks[int(op)-1]
            return puk_file


'''
    função para mostrar as opções de arquivos disponíveis para assinatura na pasta './.files' ou
    para verificação na pasta './.b64', e retornar o nome do arquivo escolhido para a função principal
'''
def opcoes_arquivos( folder:str ) -> Optional[str]:
    while True:
        files = os.listdir(folder)
        print(f"\nEscolha um dos arquivos em '{folder}':")
        for idx_file in range(len(files)):
            print(f"{idx_file+1} - {files[idx_file]}")
        print("\nDigite 'v' para voltar")
        op = input("\n> ")
        if op.lower() == 'v': return
        if not op.isalnum or op not in [str(x) for x in list(range(1,len(files)+1))]:
            print("\nOpção inválida")
        else:
            file_name = files[int(op)-1]
            return file_name

#GeradorPrimos() gera um número primo de 1024 bits
#makeKey() recebe dois primos e retorna e,n,d
#encode aplica codificação OAEP
#decode remove OAEP
#encriptar recebe mensagem com OAEP, e, n. retorna mensagem encriptada por rsa
#decriptar recebe mensagem encriptada e com OAEP, e, d. retorna mensagem apenas com OAEP aplicado
def main():    
    #exemplo do funcionamento
    #e,n,d = makeKey(GeradorPrimos(),GeradorPrimos())
    #message = "teste"    
    #encoded_msg = encode(message, (d.bit_length() + 7) // 8)
    #encriptada = encriptar(encoded_msg,d,n)
    #decriptada = decriptar(encriptada,e,n)
    #decoded_msg = decode(decriptada, (e.bit_length() + 7) // 8)
    #print(decoded_msg)


    while True:
        op = opcoes_iniciais()
        if op.lower()=='s': return(print("\nEncerrando...\n"))

        if op == "1":
            name_file = salvar_chaves()
        elif op == "2":
            prk = opcoes_chaves_privadas()
            if prk:
                file_name = opcoes_arquivos('./.files')
                if file_name: assinar_arquivo(file_name, prk)
        elif op=="3":
            puk = opcoes_chaves_publicas()
            if puk:
                file_name = opcoes_arquivos('./.b64')
                if file_name: verificar_assinatura(file_name, puk)
            
    


if __name__ == "__main__":
    main()

